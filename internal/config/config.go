package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Defaults
const (
	dbuserDefault   = "syncapod"
	dbportDefault   = 5432
	portDefault     = 3030
	grpcPortDefault = 50051
)

// Config holds variables for our server
type Config struct {
	DbUser        string `json:"db_user,omitempty"`
	DbPass        string `json:"db_pass,omitempty"`
	DbPort        int    `json:"db_port"`
	Port          int    `json:"port"`
	CertFile      string `json:"cert_file"`
	KeyFile       string `json:"key_file"`
	AlexaClientID string `json:"alexa_client_id"`
	AlexaSecret   string `json:"alexa_secret"`
	GRPCPort      int    `json:"grpc_port"`
}

// ReadConfig reads the config file encoded in JSON
func ReadConfig(r io.Reader) (*Config, error) {
	// Unmarshal into config var
	var config Config
	err := json.NewDecoder(r).Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("ReadConfig() error decoding config: %v", err)
	}
	return &config, nil
}

func readEnv(cfg *Config) {
	dbUser := os.Getenv("PG_USER")
	if len(dbUser) > 0 {
		cfg.DbUser = dbUser
	}
	dbPass := os.Getenv("PG_PASS")
	if len(dbPass) > 0 {
		cfg.DbPass = dbPass
	}
}
