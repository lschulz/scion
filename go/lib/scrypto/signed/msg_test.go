// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signed_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/scrypto/signed"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

func TestSign(t *testing.T) {
	testCases := map[string]struct {
		Signer       func(t *testing.T) crypto.Signer
		Header       signed.Header
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"ECDSAWithSHA256": {
			Signer: func(t *testing.T) crypto.Signer {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return priv
			},
			Header: signed.Header{
				SignatureAlgorithm: signed.ECDSAWithSHA256,
				Metadata:           []byte("some metadata"),
				Timestamp:          time.Now().UTC(),
				VerificationKeyID:  []byte("some key id"),
			},
			ErrAssertion: assert.NoError,
		},
		"ECDSAWithSHA384": {
			Signer: func(t *testing.T) crypto.Signer {
				priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return priv
			},
			Header: signed.Header{
				SignatureAlgorithm: signed.ECDSAWithSHA384,
				Metadata:           []byte("some metadata"),
				Timestamp:          time.Now().UTC(),
				VerificationKeyID:  []byte("some key id"),
			},
			ErrAssertion: assert.NoError,
		},
		"ECDSAWithSHA512": {
			Signer: func(t *testing.T) crypto.Signer {
				priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				require.NoError(t, err)
				return priv
			},
			Header: signed.Header{
				SignatureAlgorithm: signed.ECDSAWithSHA512,
				Metadata:           []byte("some metadata"),
				Timestamp:          time.Now().UTC(),
				VerificationKeyID:  []byte("some key id"),
			},
			ErrAssertion: assert.NoError,
		},
		"no timestamp": {
			Signer: func(t *testing.T) crypto.Signer {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return priv
			},
			Header: signed.Header{
				SignatureAlgorithm: signed.ECDSAWithSHA256,
				Metadata:           []byte("some metadata"),
				VerificationKeyID:  []byte("some key id"),
			},
			ErrAssertion: assert.NoError,
		},
		"no key ID": {
			Signer: func(t *testing.T) crypto.Signer {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return priv
			},
			Header: signed.Header{
				SignatureAlgorithm: signed.ECDSAWithSHA256,
				Metadata:           []byte("some metadata"),
				Timestamp:          time.Now().UTC(),
			},
			ErrAssertion: assert.NoError,
		},
		"no metadata": {
			Signer: func(t *testing.T) crypto.Signer {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return priv
			},
			Header: signed.Header{
				SignatureAlgorithm: signed.ECDSAWithSHA256,
				Timestamp:          time.Now().UTC(),
				VerificationKeyID:  []byte("some key id"),
			},
			ErrAssertion: assert.NoError,
		},
		"nil signer": {
			Signer: func(t *testing.T) crypto.Signer {
				return nil
			},
			Header: signed.Header{
				SignatureAlgorithm: signed.ECDSAWithSHA256,
				Metadata:           []byte("some metadata"),
				VerificationKeyID:  []byte("some key id"),
				Timestamp:          time.Now().UTC(),
			},
			ErrAssertion: assert.Error,
		},
		"unknown algorithm": {
			Signer: func(t *testing.T) crypto.Signer {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return priv
			},
			Header: signed.Header{
				SignatureAlgorithm: 1337,
				Metadata:           []byte("some metadata"),
				Timestamp:          time.Now().UTC(),
				VerificationKeyID:  []byte("some key id"),
			},
			ErrAssertion: assert.Error,
		},
		"algorithm mismatch": {
			Signer: func(t *testing.T) crypto.Signer {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return priv
			},
			Header: signed.Header{
				SignatureAlgorithm: signed.ECDSAWithSHA256,
				Metadata:           []byte("some metadata"),
				Timestamp:          time.Now().UTC(),
				VerificationKeyID:  []byte("some key id"),
			},
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body := []byte("super securely signed message")

			msg, err := signed.Sign(tc.Header, body, tc.Signer(t))
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}

			hdr, err := signed.UnverifiedHeader(msg)
			require.NoError(t, err)
			assert.Equal(t, tc.Header, *hdr)
		})
	}
}

func TestVerify(t *testing.T) {
	now := time.Now().UTC()

	testCases := map[string]struct {
		Input        func(t *testing.T) (*cryptopb.SignedMessage, crypto.PublicKey)
		Message      *signed.Message
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"ECDSAWithSHA256": {
			Input: func(t *testing.T) (*cryptopb.SignedMessage, crypto.PublicKey) {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				hdr := signed.Header{
					SignatureAlgorithm: signed.ECDSAWithSHA256,
					Metadata:           []byte("some metadata"),
					Timestamp:          now,
					VerificationKeyID:  []byte("some key id"),
				}

				s, err := signed.Sign(hdr, []byte("some body"), priv)
				require.NoError(t, err)
				return s, priv.Public()
			},
			Message: &signed.Message{
				Header: signed.Header{
					SignatureAlgorithm: signed.ECDSAWithSHA256,
					Metadata:           []byte("some metadata"),
					Timestamp:          now,
					VerificationKeyID:  []byte("some key id"),
				},
				Body: []byte("some body"),
			},
			ErrAssertion: assert.NoError,
		},
		"ECDSAWithSHA384": {
			Input: func(t *testing.T) (*cryptopb.SignedMessage, crypto.PublicKey) {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				hdr := signed.Header{
					SignatureAlgorithm: signed.ECDSAWithSHA384,
					Metadata:           []byte("some metadata"),
					Timestamp:          now,
					VerificationKeyID:  []byte("some key id"),
				}

				s, err := signed.Sign(hdr, []byte("some body"), priv)
				require.NoError(t, err)
				return s, priv.Public()
			},
			Message: &signed.Message{
				Header: signed.Header{
					SignatureAlgorithm: signed.ECDSAWithSHA384,
					Metadata:           []byte("some metadata"),
					Timestamp:          now,
					VerificationKeyID:  []byte("some key id"),
				},
				Body: []byte("some body"),
			},
			ErrAssertion: assert.NoError,
		},
		"ECDSAWithSHA512": {
			Input: func(t *testing.T) (*cryptopb.SignedMessage, crypto.PublicKey) {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				hdr := signed.Header{
					SignatureAlgorithm: signed.ECDSAWithSHA512,
					Metadata:           []byte("some metadata"),
					Timestamp:          now,
					VerificationKeyID:  []byte("some key id"),
				}

				s, err := signed.Sign(hdr, []byte("some body"), priv)
				require.NoError(t, err)
				return s, priv.Public()
			},
			Message: &signed.Message{
				Header: signed.Header{
					SignatureAlgorithm: signed.ECDSAWithSHA512,
					Metadata:           []byte("some metadata"),
					Timestamp:          now,
					VerificationKeyID:  []byte("some key id"),
				},
				Body: []byte("some body"),
			},
			ErrAssertion: assert.NoError,
		},
		"nil key": {
			Input: func(t *testing.T) (*cryptopb.SignedMessage, crypto.PublicKey) {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				hdr := signed.Header{
					SignatureAlgorithm: signed.ECDSAWithSHA512,
					Metadata:           []byte("some metadata"),
					Timestamp:          now,
					VerificationKeyID:  []byte("some key id"),
				}

				s, err := signed.Sign(hdr, []byte("some body"), priv)
				require.NoError(t, err)
				return s, nil
			},
			ErrAssertion: assert.Error,
		},
		"malformed headerAndBody": {
			Input: func(t *testing.T) (*cryptopb.SignedMessage, crypto.PublicKey) {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return &cryptopb.SignedMessage{
					HeaderAndBody: []byte("someweirdmalformedthingy"),
				}, priv
			},
			ErrAssertion: assert.Error,
		},
		"malformed header": {
			Input: func(t *testing.T) (*cryptopb.SignedMessage, crypto.PublicKey) {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				hdrAndBody := &cryptopb.HeaderAndBodyInternal{
					Header: []byte("someweirdmalformedthingy"),
					Body:   []byte("body"),
				}
				rawHdrAndBody, err := proto.Marshal(hdrAndBody)
				require.NoError(t, err)
				return &cryptopb.SignedMessage{
					HeaderAndBody: rawHdrAndBody,
				}, priv
			},
			ErrAssertion: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			signedMsg, key := tc.Input(t)
			msg, err := signed.Verify(signedMsg, key)
			tc.ErrAssertion(t, err)
			assert.Equal(t, tc.Message, msg)
		})
	}

}
