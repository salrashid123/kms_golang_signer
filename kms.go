// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"sync"

	"context"
	"fmt"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

const ()

var (
	refreshMutex = &sync.Mutex{}
)

type KMS struct {
	crypto.Signer // https://golang.org/pkg/crypto/#Signer
	// _      crypto.MessageSigner

	publicKey       crypto.PublicKey
	ProjectId       string
	LocationId      string
	KeyRing         string
	Key             string
	KeyVersion      string
	X509Certificate *x509.Certificate
	ECCRawOutput    bool // for ECC keys, output raw signatures. If false, signature is ans1 formatted

}

func NewKMSCrypto(conf *KMS) (KMS, error) {

	if conf.ProjectId == "" {
		return KMS{}, fmt.Errorf("projectID cannot be null")
	}

	ctx := context.Background()
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", conf.ProjectId, conf.LocationId, conf.KeyRing, conf.Key, conf.KeyVersion)

	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return KMS{}, fmt.Errorf("error getting kms client %v", err)
	}
	defer kmsClient.Close()

	dresp, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: parentName})
	if err != nil {
		return KMS{}, fmt.Errorf("error getting GetPublicKey %v", err)
	}
	pubKeyBlock, _ := pem.Decode([]byte(dresp.Pem))

	conf.publicKey, err = x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		return KMS{}, fmt.Errorf("error parsing PublicKey %v", err)
	}

	return *conf, nil
}

func (t KMS) Public() crypto.PublicKey {
	return t.publicKey
}

func (t KMS) TLSCertificate() (tls.Certificate, error) {

	if t.X509Certificate == nil {
		return tls.Certificate{}, fmt.Errorf("X509Certificate must be set for TLS")
	}

	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        t.X509Certificate,
		Certificate: [][]byte{t.X509Certificate.Raw},
	}, nil
}

func (t KMS) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	refreshMutex.Lock()
	defer refreshMutex.Unlock()

	ctx := context.Background()
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", t.ProjectId, t.LocationId, t.KeyRing, t.Key, t.KeyVersion)

	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		fmt.Printf("Error getting kms client %v", err)
		return nil, err
	}
	defer kmsClient.Close()

	pss, ok := opts.(*rsa.PSSOptions)
	if ok {
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash {
			fmt.Println("kmssigner: PSS salt length will automatically get set to rsa.PSSSaltLengthEqualsHash ")
		}
	}
	req := &kmspb.AsymmetricSignRequest{
		Name: parentName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		},
	}
	dresp, err := kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		fmt.Printf("Error signing with kms client %v", err)
		return nil, err
	}

	if t.ECCRawOutput {
		epub := t.Public().(*ecdsa.PublicKey)
		curveBits := epub.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}
		out := make([]byte, 2*keyBytes)
		var sigStruct struct{ R, S *big.Int }
		_, err := asn1.Unmarshal(dresp.Signature, &sigStruct)
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: can't unmarshall ecc struct %v", err)
		}
		sigStruct.R.FillBytes(out[0:keyBytes])
		sigStruct.S.FillBytes(out[keyBytes:])
		return out, nil
	}
	return dresp.Signature, nil

}

func (t KMS) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	refreshMutex.Lock()
	defer refreshMutex.Unlock()

	ctx := context.Background()
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", t.ProjectId, t.LocationId, t.KeyRing, t.Key, t.KeyVersion)

	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		fmt.Printf("Error getting kms client %v", err)
		return nil, err
	}
	defer kmsClient.Close()

	pss, ok := opts.(*rsa.PSSOptions)
	if ok {
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash {
			fmt.Println("kmssigner: PSS salt length will automatically get set to rsa.PSSSaltLengthEqualsHash ")
		}
	}
	req := &kmspb.AsymmetricSignRequest{
		Name: parentName,
		Data: msg,
	}
	dresp, err := kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		fmt.Printf("Error signing with kms client %v", err)
		return nil, err
	}

	if t.ECCRawOutput {
		epub := t.Public().(*ecdsa.PublicKey)
		curveBits := epub.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}
		out := make([]byte, 2*keyBytes)
		var sigStruct struct{ R, S *big.Int }
		_, err := asn1.Unmarshal(dresp.Signature, &sigStruct)
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: can't unmarshall ecc struct %v", err)
		}
		sigStruct.R.FillBytes(out[0:keyBytes])
		sigStruct.S.FillBytes(out[keyBytes:])
		return out, nil
	}
	return dresp.Signature, nil

}
