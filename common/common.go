package common

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type Certificate struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
}

func CreateTLSConfig(caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	// Load the CA certificate
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to add CA certificate to pool")
	}

	// Load the client certificate and key
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate and key: %v", err)
	}

	// Create and return the TLS configuration
	return &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{clientCert},
	}, nil
}

type PatroniConfig struct {
	Etcd3 struct {
		CAFile   string `yaml:"ca"`
		CertFile string `yaml:"cert"`
		KeyFile  string `yaml:"key"`
		URL      string `yaml:"url"`
	} `yaml:"etcd3"`
}

func ReadPatroniConfig(filePath string) (*PatroniConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read patroni.yml: %v", err)
	}

	var config PatroniConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal patroni.yml: %v", err)
	}

	return &config, nil
}

const (
	VersionFile    = ".last_version" // File to store the last fetched version
	RequestTimeout = 5 * time.Second // Timeout for etcd requests
)
