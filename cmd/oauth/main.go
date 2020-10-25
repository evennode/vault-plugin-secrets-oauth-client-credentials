package main

import (
	"os"

	"github.com/evennode/vault-plugin-secrets-oauth-client-credentials/pkg/backend"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	meta := &api.PluginAPIClientMeta{}

	flags := meta.FlagSet()
	flags.Parse(os.Args[1:])

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
		TLSProviderFunc:    api.VaultPluginTLSProvider(meta.GetTLSConfig()),
	})
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})

		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
