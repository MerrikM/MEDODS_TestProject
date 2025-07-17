package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	fmt.Println("путь до файла: ", filePath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла конфигурации: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("ошибка парсинга .yaml файла: %w", err)
	}

	return &cfg, nil
}
