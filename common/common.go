package common

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

func ValidateCertificate(certPEM, keyPEM string) error {
	// Decode the certificate PEM
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Decode the private key PEM
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return errors.New("failed to parse private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Validate the certificate's validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not valid yet: %v", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired: %v", cert.NotAfter)
	}

	// Validate that the certificate matches the private key
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if cert.PublicKey.(*rsa.PublicKey).N.Cmp(key.N) != 0 {
			return errors.New("certificate does not match private key")
		}
	case *ecdsa.PrivateKey:
		if cert.PublicKey.(*ecdsa.PublicKey).X.Cmp(key.X) != 0 || cert.PublicKey.(*ecdsa.PublicKey).Y.Cmp(key.Y) != 0 {
			return errors.New("certificate does not match private key")
		}
	default:
		return errors.New("unsupported private key type")
	}

	return nil
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
