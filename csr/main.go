// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/rand"

	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"

	"os"

	salkms "github.com/salrashid123/kms_golang_signer"
)

const ()

var (
	projectID = flag.String("projectID", "", "ProjectID for where the kms key is held")
	cn        = flag.String("cn", "client.domain.com", "cn value for the cert")
	filename  = flag.String("filename", "../certs/client.csr", "CSR Filename")
)

func main() {

	flag.Parse()

	r, err := salkms.NewKMSCrypto(&salkms.KMS{
		ProjectId:          *projectID,
		LocationId:         "us-central1",
		KeyRing:            "tkr1",
		Key:                "rsapss1", // "rsa1"
		KeyVersion:         "1",
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // x509.ECDSAWithSHA256,
	})

	if err != nil {
		log.Fatal(err)
	}

	createCSR(r)

}

func createCSR(t crypto.Signer) error {
	flag.Parse()

	log.Printf("Creating CSR")

	var csrtemplate = x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			Organization:       []string{"Google"},
			OrganizationalUnit: []string{"Enterprise"},
			Country:            []string{"US"},
			CommonName:         *cn,
		},
		DNSNames: []string{*cn},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, t)
	if err != nil {
		log.Fatalf("Failed to create CSR: %s", err)
	}
	certOut, err := os.Create(*filename)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", *filename, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		log.Fatalf("Failed to write data to %s: %s", *filename, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing %s  %s", *filename, err)
	}
	log.Printf("wrote %s\n", *filename)

	return nil
}
