package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"crypto/tls"

	"golang.org/x/net/http2"
)

const ()

var ()

func fronthandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/ called")
	if len(r.TLS.PeerCertificates) > 0 {
		p, ok := r.TLS.PeerCertificates[0].PublicKey.(*rsa.PublicKey)
		if ok {
			b, err := x509.MarshalPKIXPublicKey(p)
			if err != nil {
				fmt.Printf("ERROR:  could not get MarshalPKIXPublicKey: %v", err)
				return
			}
			certpem := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: b,
				},
			)
			log.Printf("Public Key from peer:  %s\n", certpem)
		}
	}

	fmt.Fprint(w, "ok")
}

func main() {

	caCert, err := ioutil.ReadFile("../certs/tls-ca.crt")
	if err != nil {
		panic(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientCaCert, err := ioutil.ReadFile("../certs/tls-ca.crt")
	if err != nil {
		panic(err)
	}
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	http.HandleFunc("/", fronthandler)

	server := &http.Server{
		Addr: ":8081",
		TLSConfig: &tls.Config{
			ClientCAs:  clientCaCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err = server.ListenAndServeTLS("../certs/server.crt", "../certs/server.key")
	log.Fatalf("Unable to start Server %v", err)

}
