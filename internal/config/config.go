package config

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v3"

	"github.com/terra-cube/key-keeper/internal/utils"
)

type Configuration struct {
	Vault       vault       `yaml:"vault"`
	Certificate certificate `yaml:"certificate"`
}

type vault struct {
	Address            string         `yaml:"address"`
	Token              string         `yaml:"token"`
	IntermediateCAPath string         `yaml:"intermediate_ca_path"`
	CertPath           string         `yaml:"cert_path"`
	Timeout            utils.Duration `yaml:"timeout"`
}

type certificate struct {
	CommonName    string         `yaml:"common_name"`
	DomainName    string         `yaml:"domain_name"`
	CaPath        string         `yaml:"ca_path"`
	CertPath      string         `yaml:"cert_path"`
	KeyPath       string         `yaml:"key_path"`
	ValidInterval utils.Duration `yaml:"valid_interval"`
}

func Read(path string) (cfg Configuration, err error) {
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
