package backend

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestConfigReadWriteDelete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage := &logical.InmemStorage{}
	backend, err := Factory(ctx, &logical.BackendConfig{})
	require.NoError(t, err)

	// Read config
	read := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configPath,
		Storage:   storage,
	}

	// Config is empty at this point
	resp, err := backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Write new config
	write := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     "foo",
			"client_secret": "bar",
			"token_url":     "token_url",
			"scopes":        "a,b,c",
		},
	}

	resp, err = backend.HandleRequest(ctx, write)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response with error: %+v", resp.Error())
	require.Nil(t, resp)

	// Read saved config
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "foo", resp.Data["client_id"])
	require.Equal(t, "token_url", resp.Data["token_url"])
	require.Equal(t, []string{"a", "b", "c"}, resp.Data["scopes"])
	require.Empty(t, resp.Data["client_secret"])

	// Delete saved config
	delete := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      configPath,
		Storage:   storage,
	}

	resp, err = backend.HandleRequest(ctx, delete)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read deleted config
	resp, err = backend.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestRequireParameters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage := &logical.InmemStorage{}
	backend, err := Factory(ctx, &logical.BackendConfig{})
	require.NoError(t, err)

	// Write new config
	write := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_secret": "bar",
			"token_url":     "token_url",
		},
	}

	resp, err := backend.HandleRequest(ctx, write)
	require.NoError(t, err)
	require.EqualError(t, resp.Error(), "Missing client ID")

	write = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id": "foo",
			"token_url": "token_url",
		},
	}

	resp, err = backend.HandleRequest(ctx, write)
	require.NoError(t, err)
	require.EqualError(t, resp.Error(), "Missing client secret")

	write = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     "foo",
			"client_secret": "bar",
		},
	}
	resp, err = backend.HandleRequest(ctx, write)
	require.NoError(t, err)
	require.EqualError(t, resp.Error(), "Missing token URL")
}
