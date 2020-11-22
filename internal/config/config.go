package config

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
)

// Defaults
const (
	dbuserDefault   = "syncapod"
	dbportDefault   = 5432
	dbnameDefault   = "syncapod"
	portDefault     = 3030
	grpcPortDefault = 50051
)

// Config holds variables for our server
type Config struct {
	DbUser        string `json:"db_user,omitempty"` // env:PG_USER
	DbPass        string `json:"db_pass,omitempty"` // env:PG_PASS
	DbPort        int    `json:"db_port"`           // env:PG_PORT
	DbName        string `json:"db_name"`           // env:PG_DB_NAME
	Port          int    `json:"port"`
	CertFile      string `json:"cert_file"`
	KeyFile       string `json:"key_file"`
	AlexaClientID string `json:"alexa_client_id"`
	AlexaSecret   string `json:"alexa_secret"`
	GRPCPort      int    `json:"grpc_port"`
}

// ReadConfig reads the config file encoded in JSON
func ReadConfig(r io.Reader) (*Config, error) {
	config := &Config{
		DbUser:   dbuserDefault,
		DbPort:   dbportDefault,
		DbName:   dbnameDefault,
		Port:     portDefault,
		GRPCPort: grpcPortDefault,
	}
	// Unmarshal into config var
	err := json.NewDecoder(r).Decode(config)
	if err != nil {
		return nil, fmt.Errorf("ReadConfig() error decoding config: %v", err)
	}
	readEnv(config)
	return config, nil
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
	dbPortString := os.Getenv("PG_PORT")
	if len(dbPortString) > 0 {
		dbPort, err := strconv.Atoi(dbPortString)
		if err != nil {
			log.Println("readEnv() error: PG_PORT not valid integer")
		}
		cfg.DbPort = dbPort
	}
	dbName := os.Getenv("PG_DB_NAME")
	if len(dbName) > 0 {
		cfg.DbName = dbName
	}
}
