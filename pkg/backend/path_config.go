package backend

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type config struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	TokenURL     string   `json:"token_url"`
	Scopes       []string `json:"scopes"`
}

func getConfig(ctx context.Context, storage logical.Storage) (*config, error) {
	entry, err := storage.Get(ctx, configPath)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	}

	c := &config{}
	if err := entry.DecodeJSON(c); err != nil {
		return nil, err
	}

	return c, nil
}

func (b *backend) configReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"client_id": c.ClientID,
			"token_url": c.TokenURL,
			"scopes":    c.Scopes,
		},
	}
	return resp, nil
}

func (b *backend) configUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	clientID, ok := data.GetOk("client_id")
	if !ok {
		return logical.ErrorResponse("Missing client ID"), nil
	}

	clientSecret, ok := data.GetOk("client_secret")
	if !ok {
		return logical.ErrorResponse("Missing client secret"), nil
	}

	tokenURL, ok := data.GetOk("token_url")
	if !ok {
		return logical.ErrorResponse("Missing token URL"), nil
	}

	c := &config{
		ClientID:     clientID.(string),
		ClientSecret: clientSecret.(string),
		TokenURL:     tokenURL.(string),
	}

	scopes, ok := data.GetOk("scopes")
	if ok {
		c.Scopes = scopes.([]string)
	}

	entry, err := logical.StorageEntryJSON(configPath, c)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) configDeleteOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configPath); err != nil {
		return nil, err
	}

	return nil, nil
}

const (
	configPath = "config"
)

var configFields = map[string]*framework.FieldSchema{
	"client_id": {
		Type:        framework.TypeString,
		Description: "Specifies the OAuth 2 client ID.",
	},
	"client_secret": {
		Type:        framework.TypeString,
		Description: "Specifies the OAuth 2 client secret.",
	},
	"token_url": {
		Type:        framework.TypeString,
		Description: "Specifies the OAuth 2 URL to retrieve token.",
	},
	"scopes": {
		Type:        framework.TypeCommaStringSlice,
		Description: "Comma separated list of default scopes for the token.",
	},
}

const configHelpSynopsis = `
Configures the OAuth client information for authorization code exchange.
`

const configHelpDescription = `
This endpoint configures the token URL, client ID, and secret for
retrieval of a token.
`

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: configPath + `$`,
		Fields:  configFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.configReadOperation,
				Summary:  "Return the current configuration for this mount.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.configUpdateOperation,
				Summary:  "Create a new client configuration or replace the configuration with new client information.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.configDeleteOperation,
				Summary:  "Delete the client configuration, invalidating all credentials.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(configHelpSynopsis),
		HelpDescription: strings.TrimSpace(configHelpDescription),
	}
}
