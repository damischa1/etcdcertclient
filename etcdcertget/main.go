package main

import (
	"context"
	"encoding/json"
	"etcdcertclient/common"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
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
	outCert := flag.String("outcert", "", "Path to output certificate file (required)")
	outKey := flag.String("outkey", "", "Path to the output private key file (required)")
	flag.Parse()

	// Ensure required parameters are provided
	if *etcdKey == "" || *caCert == "" || *clientCert == "" || *clientKey == "" {
		log.Fatalf("Usage: %s -key <etcd_key> -url <etcd_url> -ca <ca_cert> -cert <client_cert> -keyfile <client_key>", os.Args[0])
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
	resp, err := client.Get(ctx, *etcdKey)
	cancel()
	if err != nil {
		log.Fatalf("Failed to get key from etcd: %v", err)
	}

	if len(resp.Kvs) == 0 {
		log.Fatalf("Key '%s' not found in etcd", *etcdKey)
	}

	kv := resp.Kvs[0]
	currentVersion := kv.ModRevision

	// Read the last version from the version file
	lastVersion := readLastVersion(common.VersionFile)

	// Check if the current version is newer
	if currentVersion > lastVersion {
		fmt.Printf("New version detected: %d (previous: %d)\n", currentVersion, lastVersion)

		// Validate JSON content
		if !json.Valid(kv.Value) {
			log.Fatalf("Invalid JSON content for key '%s'", *etcdKey)
		}

		var certificate common.Certificate
		err := json.Unmarshal(kv.Value, &certificate)
		if err != nil {
			log.Fatalf("Error parsing key value to Certificate: ", err)
		}

		// Write JSON content to the output file
		err = os.WriteFile(*outCert, []byte(certificate.Certificate), 0644)
		if err != nil {
			log.Fatalf("Failed to write to file '%s': %v", *outCert, err)
		}

		// Write JSON content to the output file
		err = os.WriteFile(*outKey, []byte(certificate.PrivateKey), 0644)
		if err != nil {
			log.Fatalf("Failed to write to file '%s': %v", *outCert, err)
		}

		// Update the last version file
		err = os.WriteFile(common.VersionFile, []byte(strconv.FormatInt(currentVersion, 10)), 0644)
		if err != nil {
			log.Fatalf("Failed to update version file '%s': %v", common.VersionFile, err)
		}

		fmt.Printf("New certificate and private key succesfully received.\n")
	} else {
		fmt.Printf("No updates. Current version: %d, Last version: %d\n", currentVersion, lastVersion)
	}
}

func readLastVersion(versionFile string) int64 {
	// Check if the version file exists
	if _, err := os.Stat(versionFile); os.IsNotExist(err) {
		return 0
	}

	// Read the version file
	data, err := os.ReadFile(versionFile)
	if err != nil {
		log.Fatalf("Failed to read version file '%s': %v", versionFile, err)
	}

	// Parse the version number
	lastVersion, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		log.Fatalf("Invalid version number in file '%s': %v", versionFile, err)
	}

	return lastVersion
}
