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
	projectID = "mineral-minutia-820"
)

var ()

func main() {

	caCert, err := ioutil.ReadFile("CA_crt.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r, err := sal.NewKMSCrypto(&sal.KMS{
		PublicKeyFile: "client.crt",
		ProjectId:     projectID,
		LocationId:    "us-central1",
		KeyRing:       "mycacerts",
		Key:           "client",
		KeyVersion:    "4",

		ExtTLSConfig: &tls.Config{
			RootCAs:    caCertPool,
			ServerName: "localhost",
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
