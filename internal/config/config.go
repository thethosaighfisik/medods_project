package config

import (
	"os"
	"log"

	"github.com/ilyakaznacheev/cleanenv"

)

type Config struct{
	Env string `yaml:"env" env-default:"local"`
	Storage `yaml:"storage"`
	HTTPServer `yaml:"httpserver"`
	SecretString string `yaml:"secret-string"`
}

type Storage struct{
	Host string `yaml:"host"`
	Port string `yaml:"port"`
	User string `yaml:"user"`
	Password string `yaml:"password"`
	DBName string `yaml:"dbname"`
	SSLMode string `yaml:"sslmode"`

}

type HTTPServer struct{
	Address string `yaml:"address" env-default:"localhost:8085"`
}

func MustLoad() *Config{
	config_path := "./config/config.yaml"

	if config_path == "" {
		log.Fatal("CONFIG_PATH is empty")
	}

	_, err := os.Stat(config_path) 
	if os.IsNotExist(err) {
		log.Fatalf("configPath is not exist: %s", config_path)
	}
	var cfg Config

	err = cleanenv.ReadConfig(config_path, &cfg)
	if err != nil{
		log.Fatalf("error in config set:", err)
	}
	return &cfg
}


	
