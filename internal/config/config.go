package config

type Configuration struct {
	BaseDomain   string   `yaml:"base_domain"`
	Certificates []Certificate `yaml:"certificates"`
}

type Certificate struct{
	
}