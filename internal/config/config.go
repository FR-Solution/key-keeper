package config

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v3"

	"github.com/terra-cube/key-keeper/internal/controller"
	"github.com/terra-cube/key-keeper/internal/vault"
)

type Config struct {
	Vault      vault.Config      `yaml:"vault"`
	Controller controller.Config `yaml:",inline"`
}

// Read config by path.
func Read(path string) (cfg Config, err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("read config file %s: %w", path, err)
		return
	}
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		err = fmt.Errorf("unmarshal config %w", err)
		return
	}
	return
}
