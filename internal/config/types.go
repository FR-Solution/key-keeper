package config

import "time"

type Config struct {
	Issuers  []Issuer  `yaml:"issuers"`
	Resource Resources `yaml:",inline"`
}

type Issuer struct {
	Name  string `yaml:"name"`
	Vault Vault  `yaml:"vault"`
}

type Resources struct {
	Certificates []Certificate `yaml:"certificates"`
	Secrets      []Secret      `yaml:"secrets"`
}

type Certificate struct {
	Name        string        `yaml:"name"`
	IssuerRef   IssuerRef     `yaml:"issuerRef"`
	IsCA        bool          `yaml:"isCa"`
	CA          CA            `yaml:"ca"`
	Spec        Spec          `yaml:"spec"`
	HostPath    string        `yaml:"hostPath"`
	RenewBefore time.Duration `yaml:"renewBefore"`
	Trigger     []string      `yaml:"trigger"`
}

type Secret struct {
	Name      string    `yaml:"name"`
	IssuerRef IssuerRef `yaml:"issuerRef"`
	Key       string    `yaml:"key"`
	HostPath  string    `yaml:"hostPath"`
}

type Vault struct {
	Server      string        `yaml:"server"`
	Auth        Auth          `yaml:"auth"`
	Certificate CertVault     `yaml:"certificate"`
	KV          KV            `yaml:"kv"`
	Timeout     time.Duration `yaml:"timeout"`
}

type Auth struct {
	TLSInsecure bool      `yaml:"tlsInsecure"`
	CABundle    string    `yaml:"caBundle"`
	Bootstrap   Bootstrap `yaml:"bootstrap"`
	AppRole     AppRole   `yaml:"appRole"`
}

type CertVault struct {
	Role       string `yaml:"role"`
	CAPath     string `yaml:"CAPath"`
	RootCAPath string `yaml:"rootCAPath"`
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

type KV struct {
	Path string `yaml:"path"`
}

type IssuerRef struct {
	Name string `yaml:"name"`
}

type CA struct {
	ExportedKey bool `yaml:"exportedKey"`
	Generate    bool `yaml:"generate"`
}

type Spec struct {
	Subject     Subject     `yaml:"subject"`
	PrivateKey  PrivateKey  `yaml:"privateKey"`
	Hostnames   []string    `yaml:"hostnames"`
	IPAddresses IPAddresses `yaml:"ipAddresses"`
	TTL         string      `yaml:"ttl"`
}

type Subject struct {
	CommonName         string   `yaml:"commonName"`
	Country            []string `yaml:"country"`
	Locality           []string `yaml:"locality"`
	Organization       []string `yaml:"organization"`
	OrganizationalUnit []string `yaml:"organizationalUnit"`
	Province           []string `yaml:"province"`
	PostalCode         []string `yaml:"postalCode"`
	StreetAddress      []string `yaml:"streetAddress"`
	SerialNumber       string   `yaml:"serialNumber"`
}

type PrivateKey struct {
	Algorithm string `yaml:"algorithm"`
	Encoding  string `yaml:"encoding"`
	Size      int    `yaml:"size"`
}

type IPAddresses struct {
	Static     []string `yaml:"static"`
	Interfaces []string `yaml:"interfaces"`
	DNSLookup  []string `yaml:"dnsLookup"`
}
