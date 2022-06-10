package vault

import (
	"context"
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"
)

type vault struct {
	cli *api.Client
}

func New(addr, token string) (*vault, error) {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	client, err := api.NewClient(
		&api.Config{
			Address:    addr,
			HttpClient: httpClient,
		},
	)
	client.SetToken(token)

	return &vault{
		cli: client,
	}, err
}

func (c *vault) List(ctx context.Context, path string) (map[string]interface{}, error) {
	s, err := c.cli.Logical().ListWithContext(ctx, path)
	if s != nil {
		return s.Data, err
	}
	return nil, err
}

func (c *vault) Read(ctx context.Context, path string) (map[string]interface{}, error) {
	s, err := c.cli.Logical().ReadWithContext(ctx, path)
	if s != nil {
		return s.Data, err
	}
	return nil, err
}

func (c *vault) Write(ctx context.Context, path string, data map[string]interface{}) (map[string]interface{}, error) {
	s, err := c.cli.Logical().WriteWithContext(ctx, path, data)
	if s != nil {
		return s.Data, err
	}
	return nil, err
}
