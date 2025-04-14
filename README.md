# crypto.Signer, implementations for GCP KMS


This article demonstrates how you can use a [crypto.Signer](https://github.com/salrashid123/signer) implementation i wrote some years ago to make an mTLS connection using a private key that exists only in GCP KMS.

Basically, you will create a KMS key that is enabled for `RSA-PSS` or `ECDSA` Signing. 

We will then issue a `Certificate Signing Request (csr)` using the private key to sign the request.

From there, we have a local Certificate Authority that will issue the `x509` cert for the client.

We will then run an https server that requires client certificates issued by that same CA

The client will use the client `x509` and KMS private key reference to establish an mTLS connection to the server.

---

>> Note: if it wasn't clear: this repo is _not_ supported by Google


For more information, see 

* [crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules](https://github.com/salrashid123/signer)
* [mTLS with PKCS11](https://github.com/salrashid123/mtls_pkcs11)
* [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)

---

#### Create KMS Keys

First create a KMS key

```bash
export GCLOUD_USER=`gcloud config get-value core/account`

gcloud kms keyrings create tkr1 --location=us-central1

## rsa ssa
gcloud kms keys create rsa1 --keyring=tkr1 \
   --location=us-central1 --purpose=asymmetric-signing \
   --default-algorithm=rsa-sign-pkcs1-2048-sha256

gcloud kms keys add-iam-policy-binding rsa1  \
     --keyring=tkr1 --location=us-central1   \
	   --member=user:$GCLOUD_USER  --role=roles/cloudkms.signer

gcloud kms keys add-iam-policy-binding rsa1  \
     --keyring=tkr1 --location=us-central1   \
	   --member=user:$GCLOUD_USER  --role=roles/cloudkms.viewer

## rsa pss
gcloud kms keys create rsapss1 --keyring=tkr1 \
   --location=us-central1 --purpose=asymmetric-signing \
   --default-algorithm=rsa-sign-pss-2048-sha256

gcloud kms keys add-iam-policy-binding rsapss1  \
     --keyring=tkr1 --location=us-central1   \
	   --member=user:$GCLOUD_USER  --role=roles/cloudkms.signer

gcloud kms keys add-iam-policy-binding rsapss1  \
     --keyring=tkr1 --location=us-central1   \
	   --member=user:$GCLOUD_USER  --role=roles/cloudkms.viewer

## ECDSA

gcloud kms keys create ecc1 --keyring=tkr1 \
   --location=us-central1 --purpose=asymmetric-signing    --default-algorithm=ec-sign-p256-sha256

gcloud kms keys add-iam-policy-binding ecc1  \
        --keyring=tkr1 --location=us-central1  \
        --member=user:$GCLOUD_USER  --role=roles/cloudkms.signer

gcloud kms keys add-iam-policy-binding ecc1 \
        --keyring=tkr1 --location=us-central1  \
        --member=user:$GCLOUD_USER  --role=roles/cloudkms.viewer

```
![images/tlskr.png](images/tlskr.png)

```bash
$ gcloud kms keys list --keyring=tkr1 --location=us-central1

NAME                                                                      PURPOSE          ALGORITHM                   PROTECTION_LEVEL  LABELS  PRIMARY_ID  PRIMARY_STATE
projects/core-eso/locations/us-central1/keyRings/tkr1/cryptoKeys/ecc1     ASYMMETRIC_SIGN  EC_SIGN_P256_SHA256         SOFTWARE
projects/core-eso/locations/us-central1/keyRings/tkr1/cryptoKeys/mldsa1   ASYMMETRIC_SIGN  PQ_SIGN_ML_DSA_65           SOFTWARE
projects/core-eso/locations/us-central1/keyRings/tkr1/cryptoKeys/rsa1     ASYMMETRIC_SIGN  RSA_SIGN_PKCS1_2048_SHA256  SOFTWARE
projects/core-eso/locations/us-central1/keyRings/tkr1/cryptoKeys/rsapss1  ASYMMETRIC_SIGN  RSA_SIGN_PSS_2048_SHA256    SOFTWARE
```

recall the public key (your's will ofcourse be different)

```bash
$ gcloud kms keys versions get-public-key 1    --key=rsapss1 --keyring=tkr1   --location=us-central1
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/qz+6n5QBneTLdTjauM
lvVPmdfKh0Nd4F1VmXJQzv0BhhZC0yO4rIE43eMorZfzKxPaHYWfCL+UowY/+V3B
/SunFRH7gFyEl0D7Tw6EUI3LOui3UH69EecnF8qNQWtcCe1nNBo0H+xNfAqTbTi6
3/xAcG6v5gT3nhAWmnlfFCZcgyZRX7Vfy5ghdE+o7jk9mEJuwVX0CtuOI+Wg9+Jj
f/kFpds3jkGGRbjjjQtiYUfhMW7SyxuItS/g7hCk38m+wEnYromChG9fblc2E3IL
HZlW6bmIzlC4Rx7eZWQOwi8AyYp+sGScM4E9te+fvC1rTW86tmNuYXpFyi16Bkmy
0wIDAQAB
-----END PUBLIC KEY-----
```

## TLS 

You can now create a CSR and sign a TLS client certificate against a KMS backed key:

### Create a CSR


```bash
export PROJECT_ID=`gcloud config get-value core/project`

cd csr/

go run main.go --projectID=$PROJECT_ID --cn client.domain.com --filename ../certs/client.csr
```

### Sign CSR

Then initialize the CA using the certificate authority here (you can create you own CA [here](https://github.com/salrashid123/ca_scratchpad)).


```bash
cd certs/

rm -rf /tmp/kmsca
mkdir -p /tmp/kmsca

cp /dev/null /tmp/kmsca/root-ca.db
cp /dev/null /tmp/kmsca/root-ca.db.attr

echo 01 > /tmp/kmsca/root-ca.crt.srl
echo 01 > /tmp/kmsca/root-ca.crl.srl

openssl ca \
    -config root-ca.conf \
    -in client.csr \
    -out client.crt \
    -extensions client_ext
```

You can also confirm the certificate has the same public key from KMS

```bash
$ openssl x509 -pubkey -noout -in client.crt 

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/qz+6n5QBneTLdTjauM
lvVPmdfKh0Nd4F1VmXJQzv0BhhZC0yO4rIE43eMorZfzKxPaHYWfCL+UowY/+V3B
/SunFRH7gFyEl0D7Tw6EUI3LOui3UH69EecnF8qNQWtcCe1nNBo0H+xNfAqTbTi6
3/xAcG6v5gT3nhAWmnlfFCZcgyZRX7Vfy5ghdE+o7jk9mEJuwVX0CtuOI+Wg9+Jj
f/kFpds3jkGGRbjjjQtiYUfhMW7SyxuItS/g7hCk38m+wEnYromChG9fblc2E3IL
HZlW6bmIzlC4Rx7eZWQOwi8AyYp+sGScM4E9te+fvC1rTW86tmNuYXpFyi16Bkmy
0wIDAQAB
-----END PUBLIC KEY-----
```

#### Run Server

Now run the TLS Server

```bash
cd example/
go run server/main.go
```

### Run Client

```bash
cd example
go run client/client.go --projectID $PROJECT_ID
```

Once you connect, the server will show the peer certificate's public key it recieved....and surprise, its the one that matches our KMS public key

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/qz+6n5QBneTLdTjauM
lvVPmdfKh0Nd4F1VmXJQzv0BhhZC0yO4rIE43eMorZfzKxPaHYWfCL+UowY/+V3B
/SunFRH7gFyEl0D7Tw6EUI3LOui3UH69EecnF8qNQWtcCe1nNBo0H+xNfAqTbTi6
3/xAcG6v5gT3nhAWmnlfFCZcgyZRX7Vfy5ghdE+o7jk9mEJuwVX0CtuOI+Wg9+Jj
f/kFpds3jkGGRbjjjQtiYUfhMW7SyxuItS/g7hCk38m+wEnYromChG9fblc2E3IL
HZlW6bmIzlC4Rx7eZWQOwi8AyYp+sGScM4E9te+fvC1rTW86tmNuYXpFyi16Bkmy
0wIDAQAB
-----END PUBLIC KEY-----
```


## AuditLogs

If you enabled auditlogs for KMS, you will see both the csr and client request a sign API request on either side to establish the mTLS connection

![images/audit_log.png](images/audit_log.png)


## Issues, issues

#### Latency

Well...yeah, there is some and thats one of the biggest reasons this is a bit academic.  I ran this setup a couple times and saw that the API calls from my laptop to establish just a TLS connection using one KMS key added on about `150ms`...This would be faster on a compute engine or on GKE on cloud though...but its still a lot.

#### Costs

yah, that too..you're making an api call for each mtls connection..