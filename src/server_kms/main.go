package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	sal "github.com/salrashid123/misc/kms"

	"crypto/tls"

	"golang.org/x/net/http2"
)

const (
	projectID = "foo"
)

var ()

func fronthandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/ called")
	fmt.Fprint(w, "ok")
}

func healthhandler(w http.ResponseWriter, r *http.Request) {
	log.Println("heathcheck...")
	fmt.Fprint(w, "ok")
}

func main() {

	caCert, err := ioutil.ReadFile("CA_crt.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientCaCert, err := ioutil.ReadFile("CA_crt.pem")
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	r, err := sal.NewKMSCrypto(&sal.KMS{
		PublicKeyFile: "server.crt",
		ProjectId:     projectID,
		LocationId:    "us-central1",
		KeyRing:       "mycacerts",
		Key:           "server",
		KeyVersion:    "1",
		RootCAs:       caCertPool,
		ClientCAs:     clientCaCertPool,
		ClientAuth:    tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		log.Println(err)
		return
	}

	http.HandleFunc("/", fronthandler)
	http.HandleFunc("/_ah/health", healthhandler)

	var server *http.Server
	server = &http.Server{
		Addr:      ":8081",
		TLSConfig: r.TLSConfig(),
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err = server.ListenAndServeTLS("", "")
	log.Fatalf("Unable to start Server %v", err)

}
