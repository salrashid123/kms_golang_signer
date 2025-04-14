package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"flag"

	sal "github.com/salrashid123/kms_golang_signer"
)

const ()

var (
	projectID = flag.String("projectID", "", "ProjectID for where the kms key is held")
)

func main() {

	flag.Parse()

	caCert, err := os.ReadFile("../certs/root-ca.crt")
	if err != nil {
		log.Println(err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r, err := sal.NewKMSCrypto(&sal.KMS{
		ProjectId:          *projectID,
		PublicKeyFile:      "../certs/client.crt",
		LocationId:         "us-central1",
		KeyRing:            "tkr1",
		Key:                "rsapss1", // "rsa1",
		KeyVersion:         "1",
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // x509.ECDSAWithSHA256,
	})
	if err != nil {
		log.Println(err)
		return
	}

	tcrt, err := r.TLSCertificate()
	if err != nil {
		log.Println(err)
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{tcrt},
			RootCAs:      caCertPool,
			ServerName:   "server.domain.com",
			MaxVersion:   tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://localhost:8081")
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Println(string(htmlData))

}
