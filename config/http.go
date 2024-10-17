package config

type HTTP struct {
	CACert        string `yaml:"ca_cert"`
	CAPath        string `yaml:"ca_path"`
	ClientCert    string `yaml:"client_cert"`
	ClientKey     string `yaml:"client_key"`
	Insecure      bool   `yaml:"insecure"`
	TLSServerName string `yaml:"tls_server_name"`
}

func (cfg *HTTP) Preprocess() error {
	return nil
}

func (cfg *HTTP) TLSEnabled() bool {
	return cfg.CACert != "" ||
		cfg.CAPath != "" ||
		cfg.ClientCert != "" ||
		cfg.ClientKey != "" ||
		cfg.Insecure ||
		cfg.TLSServerName != ""
}
