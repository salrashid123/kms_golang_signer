package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	sal "github.com/salrashid123/misc/kms"
)

const (
	projectID = "foo"
)

var ()

func main() {

	caCert, err := ioutil.ReadFile("CA_crt.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r := &sal.KMS{
		PublicKeyFile: "client.crt",
		ProjectId:     projectID,
		LocationId:    "us-central1",
		KeyRing:       "mycacerts",
		Key:           "client",
		KeyVersion:    "1",
		RootCAs:       caCertPool,
	}

	tr := &http.Transport{
		TLSClientConfig: r.NewTLSConfig(),
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
