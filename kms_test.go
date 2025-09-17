// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	projectID  = "core-eso"
	locationID = "us-central1"
	keyRing    = "tkr1"
)

func TestKMSSignRSA(t *testing.T) {
	require.True(t, true)

	stringToSign := "foo"

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	r, err := NewKMSCrypto(&KMS{
		ProjectId:  projectID,
		LocationId: locationID,
		KeyRing:    keyRing,
		Key:        "rsa1",
		KeyVersion: "1",
	})
	require.NoError(t, err)

	s, err := r.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)

	rsaPubKey, ok := r.Public().(*rsa.PublicKey)
	require.True(t, ok)

	// rsa-sign-pkcs1-2048-sha256
	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest, s)
	require.NoError(t, err)

}

func TestKMSSignECCASN1(t *testing.T) {
	require.True(t, true)

	stringToSign := "foo"

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	r, err := NewKMSCrypto(&KMS{
		ProjectId:  projectID,
		LocationId: locationID,
		KeyRing:    keyRing,
		Key:        "ecc1",
		KeyVersion: "1",
	})
	require.NoError(t, err)

	s, err := r.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)

	ecPubKey, ok := r.Public().(*ecdsa.PublicKey)
	require.True(t, ok)

	curveBits := ecPubKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	ok = ecdsa.VerifyASN1(ecPubKey, digest[:], s)
	require.True(t, ok)
}

func TestSignRSAPSS(t *testing.T) {

	stringToSign := "foo"

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	r, err := NewKMSCrypto(&KMS{
		ProjectId:  projectID,
		LocationId: locationID,
		KeyRing:    keyRing,
		Key:        "rsapss1",
		KeyVersion: "1",
	})
	require.NoError(t, err)

	// Sign 'msg'

	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, // Use maximum salt length
		Hash:       crypto.SHA256,               // Use SHA256 for hashing
	}

	sig, err := r.Sign(rand.Reader, digest, pssOpts)
	require.NoError(t, err)

	rsaPubKey, ok := r.Public().(*rsa.PublicKey)
	require.True(t, ok)

	err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, digest, sig, pssOpts)
	require.NoError(t, err)
}
