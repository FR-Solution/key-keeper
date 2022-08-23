package controller

import "time"

type GlobalConfig struct{}

type IssuerConfig struct {
	Issuers []issuer `yaml:",inline"`
}

type RecourceConfig struct {
	Certificates []Certificate `json:"certificates"`
	Keys         Keys          `json:"keys"`
}

type issuer struct {
	Name  string      `yaml:"name"`
	Vault VaultConfig `yaml:""`
}

// VaultConfig for work with vault
type VaultConfig struct {
	Server   string `yaml:"address"`
	CABundle string `yaml:"caBundle"`
	Auth     struct {
		Bootstrap struct {
			Token string `yaml:"token"`
		} `yaml:"bootstrap"`
		AppRole struct {
			Name              string `yaml:"name"`
			Path              string `yaml:"path"`
			RoleIDLocalPath   string `yaml:"roleIDLocalPath"`
			SecretIDLocalPath string `yaml:"secretIDLocalPath"`
		}
	} `yaml:"auth"`
	RequestTimeout time.Duration `yaml:"request_timeout"`
}

type Certificate struct {
	Name     string          `yaml:"name"`
	Spec     certificateSpec `yaml:"spec"`
	HostPath string          `yaml:"hostPath"`
	Trigger  []string        `yaml:"trigger"`
}

type certificateSpec struct {
	CommonName string `yaml:"commonName"`
	Subject    struct {
		Organizations []string `yaml:"organizations"`
		Ous           []string `yaml:"ous"`
		Countries     []string `yaml:"countries"`
	} `yaml:"subject"`
	PrivateKey struct {
		Algorithm string `yaml:"algorithm"`
		Encoding  string `yaml:"encoding"`
		Size      int    `yaml:"size"`
	} `yaml:"privateKey"`
	Usages      []string `yaml:"usages"`
	DNSNames    []string `yaml:"dnsNames"`
	IPAddresses []string `yaml:"ipAddresses"`
	IssuerRef   struct {
		Name string `yaml:"name"`
	} `yaml:"issuerRef"`
	Lifespan    string        `yaml:"lifespan"`
	RenewBefore time.Duration `yaml:"renewBefore"`
}
