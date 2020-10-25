package backend

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	credMut sync.Mutex
	logger  hclog.Logger
}

const backendHelp = `
The OAuth client credentials app backend provides OAuth authorization
tokens using client credentials grant type based on secret client configuration.
`

type options struct {
	Logger hclog.Logger
}

func new(opts options) *framework.Backend {
	logger := opts.Logger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	b := &backend{
		logger: logger,
	}

	return &framework.Backend{
		Help:         strings.TrimSpace(backendHelp),
		PathsSpecial: pathsSpecial(),
		Paths:        paths(b),
		BackendType:  logical.TypeLogical,
	}
}

// Factory creates a new backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := new(options{Logger: conf.Logger})
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}
