package backend

import (
	"context"
	"crypto/sha1"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	credsPath       = "creds"
	credsPathPrefix = credsPath + "/"
)

func getTokenFromStorage(ctx context.Context, storage logical.Storage, key string) (*oauth2.Token, error) {
	entry, err := storage.Get(ctx, key)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	}

	tok := &oauth2.Token{}
	if err := entry.DecodeJSON(tok); err != nil {
		return nil, err
	}

	return tok, nil
}

func (b *backend) getToken(ctx context.Context, storage logical.Storage, c *config, key string, scopes []string) (*oauth2.Token, error) {
	tok, err := getTokenFromStorage(ctx, storage, key)
	if err != nil {
		return nil, err
	}

	// Generate new token
	if tok == nil || !tok.Valid() {
		config := &clientcredentials.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			TokenURL:     c.TokenURL,
			Scopes:       c.Scopes,
		}

		// Override default scopes if provided
		if scopes != nil {
			config.Scopes = scopes
		}

		b.credMut.Lock()
		defer b.credMut.Unlock()

		// Check if the token is not already in storage
		tok, err = getTokenFromStorage(ctx, storage, key)
		if err != nil && tok != nil && tok.Valid() {
			return tok, nil
		}

		tok, err = config.Token(ctx)
		if rErr, ok := err.(*oauth2.RetrieveError); ok {
			b.logger.Error("Invalid client credentials", "error", rErr)
			return nil, errInvalidCredentials
		} else if err != nil {
			return nil, err
		}

		entry, err := logical.StorageEntryJSON(key, tok)
		if err != nil {
			return nil, err
		}

		if err := storage.Put(ctx, entry); err != nil {
			return nil, err
		}
	}

	return tok, nil
}

// credKey hashes the name and splits the first few bytes into separate buckets
// for performance reasons.
func credKey(name string) string {
	hash := sha1.Sum([]byte(name))
	first, second, rest := hash[:2], hash[2:4], hash[4:]
	return credsPathPrefix + fmt.Sprintf("%x/%x/%x", first, second, rest)
}

// credKeyWithScopes adds scopes to the key to differentiate between
// tokens generated with different scopes.
func credKeyWithScopes(key string, scopes []string) string {
	// We assign a default single byte hashScopes if no scopes are provided.
	// This will never conflict with 20 byte sha1 sum from credKey.
	hashScopes := [20]byte{65}
	sort.Strings(scopes)
	if scopes != nil {
		hashScopes = sha1.Sum([]byte(strings.Join(scopes, ",")))
	}

	return key + fmt.Sprintf("/%x", hashScopes)
}

func (b *backend) credsReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return logical.ErrorResponse("Not configured"), nil
	}

	scopes := c.Scopes
	if d, ok := data.GetOk("scopes"); ok {
		scopes = d.([]string)
	}

	key := credKeyWithScopes(credKey(data.Get("name").(string)), scopes)
	tok, err := b.getToken(ctx, req.Storage, c, key, scopes)

	if err == errInvalidCredentials {
		return logical.ErrorResponse("Invalid client credentials"), nil
	} else if err != nil {
		return nil, err
	} else if tok == nil {
		return nil, nil
	} else if !tok.Valid() {
		return logical.ErrorResponse("Token expired"), nil
	}

	rd := map[string]interface{}{
		"access_token": tok.AccessToken,
		"expires":      tok.Expiry,
	}

	resp := &logical.Response{
		Data: rd,
	}
	return resp, nil
}

func (b *backend) credsDeleteOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.credMut.Lock()
	defer b.credMut.Unlock()

	key := credKey(data.Get("name").(string))
	scopes, err := req.Storage.List(ctx, key+"/")
	if err != nil {
		return nil, err
	}

	for _, scope := range scopes {
		if err := req.Storage.Delete(ctx, key+"/"+scope); err != nil {
			return nil, err
		}
	}

	return nil, nil
}

var credsFields = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "Specifies the name of the credential.",
	},
	"scopes": {
		Type:    framework.TypeCommaStringSlice,
		Default: "Comma separated list of scopes for the token to override default scopes from config.",
	},
}

// Allow characters not special to urls or shells
// Derived from framework.GenericNameWithAtRegex
func credentialNameRegex(name string) string {
	return fmt.Sprintf(`(?P<%s>\w(([\w.@~!_,:^-]+)?\w)?)`, name)
}

const credsHelpSynopsis = `
Provides access tokens for client credentials.
`

const credsHelpDescription = `
This endpoint allows users to retrieve tokens.
`

func pathCreds(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: credsPathPrefix + credentialNameRegex("name") + `$`,
		Fields:  credsFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.credsReadOperation,
				Summary:  "Get a current access token for this credential.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.credsDeleteOperation,
				Summary:  "Remove a credential.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(credsHelpSynopsis),
		HelpDescription: strings.TrimSpace(credsHelpDescription),
	}
}
