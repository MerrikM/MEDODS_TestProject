package config

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	JWT      JWTConfig      `yaml:"jwt"`
	Webhook  WebhookConfig  `yaml:"webhook"`
}

type ServerConfig struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	BasePath string `yaml:"base_path"`
}

type DatabaseConfig struct {
	Host             string `yaml:"host"`
	Port             string `yaml:"port"`
	Driver           string `yaml:"driver"`
	ConnectionString string `yaml:"connection_string"`
}

type JWTConfig struct {
	SecretKey       string `yaml:"secret_key"`
	AccessTokenTTL  string `yaml:"access_token_ttl"`
	RefreshTokenTTL string `yaml:"refresh_token_ttl"`
}

type WebhookConfig struct {
	URL     string `yaml:"url"`
	Timeout string `yaml:"timeout"`
}
