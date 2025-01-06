package main

import (
	"context"
	"encoding/json"
	"etcdcertclient/common"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func main() {
	// Define and parse command-line flags
	configFile := flag.String("config", "", "Path to the etcd3 YAML configuration file (required)")
	etcdKey := flag.String("key", "", "The etcd key where certificates are stored to fetch (required)")
	inCert := flag.String("incert", "", "Path to input certificate file (required)")
	inKey := flag.String("inkey", "", "Path to the input private key file (required)")
	flag.Parse()

	// Ensure required parameters are provided
	if *etcdKey == "" || *configFile == "" {
		log.Fatalf("Usage: %s -config <config_file> -key <etcd_key> -incert <certificate> -inkey <privatekey>", os.Args[0])
	}

	// Read the etcd3 YAML configuration
	config, err := common.ReadPatroniConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to read etcd3 YAML configuration: %v", err)
	}

	// Read the certificate file
	cert, err := os.ReadFile(*inCert)
	if err != nil {
		log.Fatalf("Failed to read input certificate file '%s': %v", *inCert, err)
	}

	// Read the private key file
	privateKey, err := os.ReadFile(*inKey)
	if err != nil {
		log.Fatalf("Failed to read input private key file '%s': %v", *inKey, err)
	}

	certificate := common.Certificate{Certificate: string(cert), PrivateKey: string(privateKey)}

	// Convert certificate to JSON
	jsonCertificate, err := json.Marshal(certificate)
	if err != nil {
		log.Fatalf("Failed to convert the certificate to JSON: %v", err)
	}

	// Load the certificates
	tlsConfig, err := common.CreateTLSConfig(config.Etcd3.CAFile, config.Etcd3.CertFile, config.Etcd3.KeyFile)
	if err != nil {
		log.Fatalf("Failed to create TLS configuration: %v", err)
	}

	// Connect to etcd
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{config.Etcd3.URL},
		TLS:         tlsConfig,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to connect to etcd: %v", err)
	}
	defer client.Close()

	// Put the certificate and private key to etcd
	ctx, cancel := context.WithTimeout(context.Background(), common.RequestTimeout)
	_, err = client.Put(ctx, *etcdKey, string(jsonCertificate))
	cancel()
	if err != nil {
		log.Fatalf("Failed to put key to etcd: %v", err)
	}

	fmt.Printf("Certificate and private key successfully put to etcd.\n")
}
