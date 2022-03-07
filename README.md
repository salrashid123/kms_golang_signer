
# mTLS with Google Cloud KMS

A couple weeks back I hacked golang's [crypto.Signer](https://golang.org/pkg/crypto/#Signer) and [crypto.Decrypter](https://golang.org/pkg/crypto/#Decrypter) interface to the `Trusted Platform Module (TPM)` go interface i've been working with lately.  While working with that, I knew you can seal a key to a TPM and make it sign for some data just like with KMS...I knew TLS connections primarily use signatures during the exchange so i thought: _is there anyway to add a signer interface to [go-tpm](https://github.com/google/go-tpm) such that i can use the key in the TPM with SSL_?  Yep, that involves having something implement the `crypto.Signer` interface (mostly).

The implementation i have for that is just a hack [here](https://github.com/salrashid123/signer)/

So...coming back to KMS..this repo is an extension of that idea where you can run an HTTPs server and client where the private keys are save in KMS.

(yes, i know, latency, practicality etc but this is (at the moment) for amusement so..)

At a high level, you use your `CA` (wherever it is), to define  a set of keypairs for an HTTPS `server` and `client`.  You then embed the certs into [Cloud KMS](https://cloud.google.com/kms/) with just RSA sign capability and then restrict access to those keys via IAM.

The HTTPS sever has credentials to access the server key to only Sign.  The client has credentials to the client key to only sign.  If you define a golang `TLSConfig` provider that implements the `crypto.Singer` capability, the standard golang `net/http` module will delegate the crypto operations to your implementation. In ourcase the `Sign()` request coming for the go library inturn just makes a cloud KMS api call...thats it.

You ofcourse don't need to run mTLS here..you can just use KMS for one direction of the session.

>> Note: if it wasn't clear: this repo is _not_ supported by Google

### crypto.Signer, crypto.Decrypter Implementation for KMS

At the heart of all this is the wrapper implementation i hacked here that wraps KMS api calls with the `Signer`

- [https://github.com/salrashid123/signer/blob/master/kms/kms.go](https://github.com/salrashid123/signer/blob/master/kms/kms.go)


>> IMPORTANT: you must use at **MOST** go1.13 since versions beyond that uses RSA-PSS (ref [32425](https://github.com/golang/go/issues/32425)) and KMS only support RSA

So a sample sever for TLS looks prettymuch like what you'd expect anyway

```golang
package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	sal "github.com/salrashid123/signer/kms"
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


func main() {

	caCert, err := ioutil.ReadFile("certs/tls-ca.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r, err := sal.NewKMSCrypto(&sal.KMS{
		PublicKeyFile: "certs/client.crt",
		ProjectId:     projectID,
		LocationId:    "us-central1",
		KeyRing:       "mycacerts",
		Key:           "client",
		KeyVersion:    "1",
		ExtTLSConfig: &tls.Config{
			RootCAs:    caCertPool,
		},	
	})
	if err != nil {
		log.Fatalf(err)
	}

	http.HandleFunc("/", fronthandler)

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
```

Notes:
- Yes, i didn't implement all the parameters for the `TlSConfig`...but its enough to make it work for now
- Yes, i should not create new KMS clients everytime (don't be lazy, sal)
- Yes, why do this anyway? (see the bottom of the repo)

---

Anyway, if you're still interested: 

### Generate local CA

First we need to generate a CA an certificates we want to import.  The following describes the basic flow derived from a prior article [here](https://github.com/salrashid123/ca_scratchpad) to create a CA, a set of server and client certificates.  We are defining the server cert to have 'CN=localhost` but you are free to define wherever you with to host the service

NOTE, i used `Signature Algorithm: sha256WithRSAEncryption` for my CA and certs



Alternatively, you can use the certs/keys under the `certs/` folder as a reference

### Create KMS KeyRing and ImportJob

First step is to setup the keyring itself:

https://cloud.google.com/kms/docs/importing-a-key

```bash
export LOCATION=us-central1
export KEYRING_NAME=mycacerts
export IMPORT_JOB=kmskeyimporter
export VERSION=1

gcloud kms keyrings create $KEYRING_NAME --location $LOCATION

gcloud kms import-jobs create $IMPORT_JOB \
  --location $LOCATION \
  --keyring $KEYRING_NAME \
  --import-method rsa-oaep-3072-sha1-aes-256 \
  --protection-level hsm
```
### Create import keys on Cloud console

On the cloud console, navigate to the KMS key cited above and simply define the `serverpss` and `clientpss` as shown below.  You do _not_ need to import anything yet; we will format and use gcloud shortly. 

Remember while defining the keys, specify

* `Asymmetric Sign`:  
* `2048 bit RSA key PSS padding - SHA256 Digest`
* Select _"Import Key Material"_
* Click the "Create" button but _do not_ import anything (we ill do that later in the next step; simply navigate back)

![images/server.png](images/server.png)

![images/client.png](images/client.png)

### Format private keys for import

We need to [format the keys](https://cloud.google.com/kms/docs/formatting-keys-for-import) for importing into the HSM as described in:

```bash
openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER  -in certs/server.key -out certs/server_formatted.key
openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER  -in certs/client.key -out certs/client_formatted.key
```

### Import the keys into the HSM

```bash
gcloud  kms keys versions import \
  --import-job $IMPORT_JOB --location $LOCATION  \
  --keyring $KEYRING_NAME   --key serverpss \
  --algorithm rsa-sign-pss-2048-sha256 \
  --target-key-file  certs/server_formatted.key

gcloud  kms keys versions import \
  --import-job $IMPORT_JOB --location $LOCATION  \
  --keyring $KEYRING_NAME   --key clientpss \
  --algorithm rsa-sign-pss-2048-sha256 \
  --target-key-file  certs/client_formatted.key
```

You can verify the status of the import job by running.  When the job is completed, you should see `state: ENABLED`

```bash
gcloud kms keys versions describe $VERSION \
  --location $LOCATION \
  --keyring $KEYRING_NAME \
  --key serverpss
```

>> At this point, you can delete `server.key` and `client.key` private keys as its now save(er) inside KMS.


Get the key VERSIONS you just imported.  For me this specific key version i imported is number `1` for the server and client

```bash
$ gcloud kms keys versions list --location $LOCATION --keyring $KEYRING_NAME --key serverpss
NAME                                                                                                            STATE
projects/mineral-minutia-820/locations/us-central1/keyRings/mycacerts/cryptoKeys/serverpss/cryptoKeyVersions/1  ENABLED

$ gcloud kms keys versions list --location $LOCATION --keyring $KEYRING_NAME --key clientpss
NAME                                                                                                            STATE
projects/mineral-minutia-820/locations/us-central1/keyRings/mycacerts/cryptoKeys/clientpss/cryptoKeyVersions/1  ENABLED
```

### Specify IAM permission on the keys for 

If you are running this tutorial somewhere you  are already authenticated via application default credentials, you should already have IAM permissions inherited. If not, for each key you've just defined, assign the `Cloud KMS CryptoKey Signer` role to the account that will run the client and server

### Run mTLS Server

Edit `src/server_kms/main.go` and 

set the `projectID` const variable
set the key version you used (for me its `1`)

```
export GOPATH=$GOPATH:`pwd`

go run src/server_kms/main.go
```


```
curl -vvvvv \
  -H "host: localhost" \
  --resolve  http.domain.com:8081:127.0.0.1 \
  --cert certs/client.crt \
  --key certs/client.key \
  --cacert certs/tls-ca.crt \
  https://localhost:8081
```


### Run mTLS Client

Edit `src/client/main.go` and set

set the `projectID` const variable
set the key version you used (for me its `5`)


```
export GOPATH=$GOPATH:`pwd`

go run src/client/main.go
```

What you should see is a simple ok...but what that shows is mTLS between the client and server where the private keys used to make the mTLS connection is hosted on cloud KMS...



## AuditLogs

If you enabled auditlogs for KMS, you will see both the client and server request a sign API request on either side to establish the mTLS connection

![images/audit_log.png](images/audit_log.png)

## Issues, issues

#### Latency

Well...yeah, there is some and thats one of the biggest reasons this is a bit academic.  I ran this setup a couple times and saw that the API calls from my laptop to establish just a TLS connection using one KMS key added on about `150ms`...This would be faster on a compute engine or on GKE on cloud though...but its still a lot.

#### Authentication

The permission to even access the KMS keys to do anything requires bootstrapping `Application Default Credentials`...which means the system will need some context to do anything.  The example here used my own user account but you can use a serviceAccount credential, GCE Metadata server...or later on what is i've been working on here is the Trusted Platform Module that saves the credentials.

- [TPM2-TSS-Engine hello world and Google Cloud Authentication](https://github.com/salrashid123/tpm2_evp_sign_decrypt)
- [TPM crypto.Signer](https://github.com/salrashid123/misc/blob/master/tpm/tpm.go)
- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)

#### Why do all this anyway?

I'm not sure at the moment...

---


## Appendix

### Using crypto.Decrypter

If you want to test crypto.Decryptor, assign `Cloud KMS CryptoKey Decrypter` role and uncomment.  You will need to create a _new_ keypair using your CA (call it `decrypter`) and follow the procedure above.  The distiction here is that while you define the key in KMS, st it to Decrypt (not sign)

```golang

	publicKeyFile := "decrypter.pem"
	publicPEM, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		log.Fatalf("Unable to read keys %v", err)
	}
	pubKeyBlock, _ := pem.Decode((publicPEM))
	ifc, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	pkey, ok := ifc.(*rsa.PublicKey)
	if !ok {
		log.Fatal("Unable to extract PublicKey")
	}
	hash := sha256.New()
	msg := []byte("foo")
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pkey, msg, nil)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Encrypted Data: %v", base64.StdEncoding.EncodeToString(ciphertext))

	r, err := sal.NewKMSCrypto(&sal.KMS{
		ProjectId:  "mineral-minutia-820",
		LocationId: "us-central1",
		KeyRing:    "mycacerts",
		Key:        "decrypter",
		KeyVersion: "1",
	})
	if err != nil {
		log.Println(err)
		return
	}

	plaintext, err := r.Decrypt(rand.Reader, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Decrypted Data: %v ", string(plaintext))
  
```