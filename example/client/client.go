package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"flag"

	sal "github.com/salrashid123/signer/kms"
)

const ()

var (
	projectID = flag.String("projectID", "", "ProjectID for where the kms key is held")
)

func main() {

	flag.Parse()

	caCert, err := ioutil.ReadFile("../certs/tls-ca.crt")
	if err != nil {
		log.Println(err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r, err := sal.NewKMSCrypto(&sal.KMS{
		ProjectId:          *projectID,
		PublicKeyFile:      "../certs/client.crt",
		LocationId:         "global",
		KeyRing:            "tlskr",
		Key:                "k1",
		KeyVersion:         "1",
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // required for go 1.15+ TLS
		ExtTLSConfig: &tls.Config{
			RootCAs:    caCertPool,
			ServerName: "server.domain.com",
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
