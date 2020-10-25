package backend

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type MockRoundTripper struct {
	Handler http.Handler
}

func (mrt *MockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	mrt.Handler.ServeHTTP(w, r)
	return w.Result(), nil
}

func TestTokenRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	i := 1
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			// Validate Client ID and Client Secret
			authHeader := r.Header.Get("Authorization")
			require.True(t, strings.HasPrefix(authHeader, "Basic "))

			auth, err := base64.StdEncoding.DecodeString(authHeader[6:])
			require.NoError(t, err)
			assert.Equal(t, "foo:bar", string(auth))

			b, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)

			data, err := url.ParseQuery(string(b))
			require.NoError(t, err)

			switch data.Get("grant_type") {
			case "client_credentials":
				assert.Equal(t, "client_credentials", data.Get("grant_type"))
				assert.True(t, strings.HasPrefix(data.Get("scope"), "a b c"))

				expiresIn := 5
				if i > 1 {
					expiresIn = 3600
				}

				w.Write([]byte(fmt.Sprintf(`access_token=abcd%d&token_type=bearer&expires_in=%d`, i, expiresIn)))
				i++
			default:
				assert.Fail(t, "unexpected `grant_type` value: %q", data.Get("grant_type"))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	c := &http.Client{Transport: &MockRoundTripper{Handler: h}}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c)

	storage := &logical.InmemStorage{}
	backend, err := Factory(ctx, &logical.BackendConfig{})
	require.NoError(t, err)

	// Write new config
	write := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     "foo",
			"client_secret": "bar",
			"token_url":     "http://localhost/token",
			"scopes":        "a,b,c",
		},
	}

	resp, err := backend.HandleRequest(ctx, write)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read token
	read := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPath + "/user",
		Storage:   storage,
	}

	// Get new token - shall be expired
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.EqualError(t, resp.Error(), "Token expired")

	// Token should not be expired
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response with error: %+v", resp.Error())
	require.Equal(t, "abcd2", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expires"])

	// Token should come from storage
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response with error: %+v", resp.Error())
	require.Equal(t, "abcd2", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expires"])

	// Change user
	read.Path = credsPath + "/user2"

	// Should receive new not expired token
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response with error: %+v", resp.Error())
	require.Equal(t, "abcd3", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expires"])

	// Token should come from storage
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response with error: %+v", resp.Error())
	require.Equal(t, "abcd3", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expires"])

	// Override scopes
	read.Data = map[string]interface{}{
		"scopes": "a,b,c",
	}

	// Existing token with overridden scopes shall return the same token
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response with error: %+v", resp.Error())
	require.Equal(t, "abcd3", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expires"])

	// Override scopes
	read.Data = map[string]interface{}{
		"scopes": "a,b,c,d,e",
	}

	// Existing token with updated scopes shall return new token
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response with error: %+v", resp.Error())
	require.Equal(t, "abcd4", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expires"])

	// Existing token with the same scopes
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response with error: %+v", resp.Error())
	require.Equal(t, "abcd4", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expires"])

	// Existing token with the same scopes in different order
	read.Data["scopes"] = "a,b,c,e,d"
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response with error: %+v", resp.Error())
	require.Equal(t, "abcd4", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expires"])

	// Delete token
	delete := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      credsPath + "/user2",
		Storage:   storage,
	}

	resp, err = backend.HandleRequest(ctx, delete)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Token should be regenerated
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response with error: %+v", resp.Error())
	require.Equal(t, "abcd5", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expires"])
}

func TestReadNotConfigured(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage := &logical.InmemStorage{}
	backend, err := Factory(ctx, &logical.BackendConfig{})
	require.NoError(t, err)

	// Read token
	read := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPath + "/user",
		Storage:   storage,
	}

	// Config is empty at this point
	resp, err := backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.EqualError(t, resp.Error(), "Not configured")
}

func TestReadInvalidCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	c := &http.Client{Transport: &MockRoundTripper{Handler: h}}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c)

	storage := &logical.InmemStorage{}
	backend, err := Factory(ctx, &logical.BackendConfig{})
	require.NoError(t, err)

	// Write new config
	write := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     "foo",
			"client_secret": "bar",
			"token_url":     "http://localhost/token",
		},
	}

	resp, err := backend.HandleRequest(ctx, write)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read token
	read := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPath + "/user",
		Storage:   storage,
	}

	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.EqualError(t, resp.Error(), "Invalid client credentials")
}
