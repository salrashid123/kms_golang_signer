package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	sal "github.com/salrashid123/signer/kms"
)

const (
	projectID = "YOUR_PROJECT_ID"
)

var ()

func main() {

	caCert, err := ioutil.ReadFile("certs/tls-ca.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r, err := sal.NewKMSCrypto(&sal.KMS{
		PublicKeyFile:      "certs/client.crt",
		ProjectId:          projectID,
		LocationId:         "us-central1",
		KeyRing:            "mycacerts",
		Key:                "clientpss",
		KeyVersion:         "2",
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // required for go 1.15+ TLS
		ExtTLSConfig: &tls.Config{
			RootCAs:    caCertPool,
			ServerName: "localhost",
			MaxVersion: tls.VersionTLS12,
		},
	})
	if err != nil {
		log.Println(err)
		return
	}

	tr := &http.Transport{
		TLSClientConfig: r.TLSConfig(),
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://localhost:8081")
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf(string(htmlData))

}
