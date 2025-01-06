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
	etcdKey := flag.String("key", "", "The etcd key where certificates are stored to fetch (required)")
	etcdURL := flag.String("url", "https://localhost:2379", "The etcd URL (default: https://localhost:2379)")
	caCert := flag.String("ca", "", "Path to the CA certificate file (required)")
	clientCert := flag.String("cert", "", "Path to the client certificate file (required)")
	clientKey := flag.String("keyfile", "", "Path to the client private key file (required)")
	inCert := flag.String("incert", "", "Path to output certificate file (required)")
	inKey := flag.String("inkey", "", "Path to the output private key file (required)")
	flag.Parse()

	// Ensure required parameters are provided
	if *etcdKey == "" || *caCert == "" || *clientCert == "" || *clientKey == "" {
		log.Fatalf("Usage: %s -key <etcd_key> -url <etcd_url> -ca <ca_cert> -cert <client_cert> -keyfile <client_key> -incert <certificate> -inkey <privatekey>", os.Args[0])
	}

	// Read the certificate file
	cert, err := os.ReadFile(*inCert)
	if err != nil {
		log.Fatalf("Failed to read input certificate file '%s': %v", inCert, err)
	}

	// Read the private key file
	privateKey, err := os.ReadFile(*inKey)
	if err != nil {
		log.Fatalf("Failed to read input private key file '%s': %v", inKey, err)
	}

	certificate := common.Certificate{Certificate: string(cert), PrivateKey: string(privateKey)}

	// Convert certificate to JSON
	jsonCertificate, err := json.Marshal(certificate)

	if err != nil {
		log.Fatalf("Failed to convert the certificat to JSON")
	}

	// Load the certificates
	tlsConfig, err := common.CreateTLSConfig(*caCert, *clientCert, *clientKey)
	if err != nil {
		log.Fatalf("Failed to create TLS configuration: %v", err)
	}

	// Connect to etcd
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{*etcdURL},
		TLS:         tlsConfig,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to connect to etcd: %v", err)
	}
	defer client.Close()

	// Get the current version and content of the key
	ctx, cancel := context.WithTimeout(context.Background(), common.RequestTimeout)

	_, err = client.Put(ctx, *etcdKey, string(jsonCertificate))

	cancel()
	if err != nil {
		log.Fatalf("Failed to put key to etcd: %v", err)
	}
	fmt.Printf("Certificate and private key succesfully put to etcd.\n")
}
