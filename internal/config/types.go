package config

import "time"

type Config struct {
	Issueres []Issuer  `yaml:"issueres"`
	Resource Resources `yaml:",inline"`
}

type Issuer struct {
	Name  string `yaml:"name"`
	Vault Vault  `yaml:"vault"`
}

type Resources struct {
	Certificates []Certificate `yaml:"certificate"`
	Keys         []Key         `yaml:"key"`
}

type Certificate struct {
	Name            string        `yaml:"name"`
	IssuerRef       IssuerRef     `yaml:"issuerRef"`
	IsCA            bool          `yaml:"isCa"`
	Spec            Spec          `yaml:"spec"`
	HostPath        string        `yaml:"hostPath"`
	VaultPath       string        `yaml:"vaultPath"`
	VaultRole       string        `yaml:"vaultRole"`
	VaultRootCAPath string        `yaml:"vaulRrootCAPath"`
	Trigger         []string      `yaml:"trigger"`
	RenewBefore     time.Duration `yaml:"renewBefore" `
}

type Key struct {
	Name       string     `yaml:"name"`
	IssuerRef  IssuerRef  `yaml:"issuerRef"`
	PrivateKey PrivateKey `yaml:"privateKey"`
	Public     bool       `yaml:"public"`
	HostPath   string     `yaml:"hostPath"`
}

type IssuerRef struct {
	Name string `yaml:"name"`
}

type Vault struct {
	Server  string        `yaml:"address"`
	Auth    Auth          `yaml:"auth"`
	KV      KV            `yaml:"kv"`
	Timeout time.Duration `yaml:"timeout"`
}

type Auth struct {
	TLSInsecure bool      `yaml:"tlsInsecure"`
	CABundle    string    `yaml:"caBundle"`
	Bootstrap   Bootstrap `yaml:"bootstrap"`
	AppRole     AppRole   `yaml:"appRole"`
}

type KV struct {
	Path string `yaml:"paths"`
}

type Bootstrap struct {
	Token string `yaml:"token"`
}

type AppRole struct {
	Name              string `yaml:"name"`
	Path              string `yaml:"path"`
	RoleIDLocalPath   string `yaml:"roleIDLocalPath"`
	SecretIDLocalPath string `yaml:"secretIDLocalPath"`
}

type Spec struct {
	CommonName  string     `yaml:"commonName"`
	Subject     Subject    `yaml:"subject"`
	PrivateKey  PrivateKey `yaml:"privateKey"`
	Usages      []string   `yaml:"usages"`
	Hostnames   []string   `yaml:"hostnames"`
	IPAddresses []string   `yaml:"ipAddresses"`
	TTL         string     `yaml:"ttl"`
}

type Subject struct {
	Countries           []string `yaml:"countries"`
	Localities          []string `yaml:"localities"`
	OrganizationalUnits []string `yaml:"organizationalUnits"`
	Organizations       []string `yaml:"organizations"`
	PostalCodes         []string `yaml:"postalCodes"`
	Provinces           []string `yaml:"provinces"`
	SerialNumber        string   `yaml:"serialNumber"`
	StreetAddresses     []string `yaml:"streetAddresses"`
}

type PrivateKey struct {
	Algorithm string `yaml:"algorithm"`
	Encoding  string `yaml:"encoding"`
	Size      int    `yaml:"size"`
}
