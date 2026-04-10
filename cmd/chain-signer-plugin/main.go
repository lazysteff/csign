package main

import (
	"os"

	"github.com/chain-signer/chain-signer/pkg/backend"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	vaultplugin "github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	_ = flags.Parse(os.Args[1:])

	tlsProvider := api.VaultPluginTLSProvider(apiClientMeta.GetTLSConfig())
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "chain-signer",
		Level: hclog.Info,
	})

	if err := vaultplugin.Serve(&vaultplugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
		TLSProviderFunc:    tlsProvider,
		Logger:             logger,
	}); err != nil {
		logger.Error("plugin exited", "error", err)
		os.Exit(1)
	}
}
