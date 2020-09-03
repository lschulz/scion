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

package signed

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/serrors"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

// Header represents the signed message header.
type Header struct {
	// SignatureAlgorithm indicates the signature algorithm.
	SignatureAlgorithm SignatureAlgorithm
	// VerificationKeyID is the optional identifier for the verification key.
	VerificationKeyID []byte
	// Timestamp is the optional signature creation time.
	Timestamp time.Time
	// Metadata is optional arbitrary data that is covered by the signature.
	Metadata []byte
}

// Message represents the signed message.
type Message struct {
	Header Header
	Body   []byte
}

// Sign creates a signed message.
func Sign(hdr Header, body []byte, signer crypto.Signer) (*cryptopb.SignedMessage, error) {
	if signer == nil {
		return nil, serrors.New("singer must not be nil")
	}
	if err := checkPubKeyAlgo(hdr.SignatureAlgorithm, signer.Public()); err != nil {
		return nil, err
	}
	var ts *timestamp.Timestamp
	if !hdr.Timestamp.IsZero() {
		var err error
		ts, err = ptypes.TimestampProto(hdr.Timestamp)
		if err != nil {
			return nil, serrors.WrapStr("converting timestamp", err)
		}
	}

	inputHdr := &cryptopb.Header{
		SignatureAlgorithm: hdr.SignatureAlgorithm.toPB(),
		Metadata:           hdr.Metadata,
		VerificationKeyId:  hdr.VerificationKeyID,
		Timestamp:          ts,
	}
	rawHdr, err := proto.Marshal(inputHdr)
	if err != nil {
		return nil, serrors.WrapStr("packing header", err)
	}
	hdrAndBody := &cryptopb.HeaderAndBodyInternal{
		Header: rawHdr,
		Body:   body,
	}
	rawHdrAndBody, err := proto.Marshal(hdrAndBody)
	if err != nil {
		return nil, serrors.WrapStr("packing signature input", err)
	}
	input, hashAlgo := computeSignatureInput(hdr.SignatureAlgorithm, rawHdrAndBody)
	signature, err := signer.Sign(rand.Reader, input, hashAlgo)
	if err != nil {
		return nil, err
	}
	return &cryptopb.SignedMessage{
		HeaderAndBody: rawHdrAndBody,
		Signature:     signature,
	}, nil
}

// Verify verifies the signed message.
func Verify(signed *cryptopb.SignedMessage, key crypto.PublicKey) (*Message, error) {
	if key == nil {
		return nil, serrors.New("public key must not be nil")
	}
	hdr, body, err := extractHeaderAndBody(signed)
	if err != nil {
		return nil, serrors.WrapStr("extracting header", err)
	}
	if err := checkPubKeyAlgo(hdr.SignatureAlgorithm, key); err != nil {
		return nil, err
	}

	input, _ := computeSignatureInput(hdr.SignatureAlgorithm, signed.HeaderAndBody)

	switch pub := key.(type) {
	case *ecdsa.PublicKey:
		type ecdsaSignature struct {
			R, S *big.Int
		}

		// XXX(roosd): Copied from x509/x509.go:checkSignature.
		var sig ecdsaSignature
		if rest, err := asn1.Unmarshal(signed.Signature, &sig); err != nil {
			return nil, err
		} else if len(rest) != 0 {
			return nil, serrors.New("trailing data after ECDSA signature")
		}
		if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
			return nil, errors.New("ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub, input, sig.R, sig.S) {
			return nil, errors.New("ECDSA verification failure")
		}
	default:
		return nil, serrors.New("public key algorithm not implemented")
	}
	return &Message{
		Header: *hdr,
		Body:   body,
	}, nil
}

func computeSignatureInput(algo SignatureAlgorithm, hdrAndBody []byte) ([]byte, crypto.Hash) {
	hash := signatureAlgorithmDetails[algo].hash
	if hash == 0 {
		return hdrAndBody, hash
	}
	if !hash.Available() {
		panic(fmt.Sprintf("unavailable hash algorithm: %v", hash))
	}
	h := hash.New()
	h.Write(hdrAndBody)
	return h.Sum(nil), hash
}

func checkPubKeyAlgo(signAlgo SignatureAlgorithm, pubKey crypto.PublicKey) error {
	d, ok := signatureAlgorithmDetails[signAlgo]
	if !ok {
		return serrors.New("unsupported signature algorithm", "signature_algorithm", signAlgo)
	}
	switch pubKey.(type) {
	case *ecdsa.PublicKey:
		if d.pubKeyAlgo != pkECDSA {
			return serrors.New("signature algorithm is incompatible with key",
				"signature_algorithm", signAlgo, "public_key_algorithm", "ECDSA")
		}
		return nil
	default:
		return serrors.New("unsupported public key algorithm", "type", fmt.Sprintf("%T", pubKey))
	}
}

// UnverifiedHeader extracts the header from the signed message without
// verification. The caller can use it to identify the appropriate key for
// verification.
func UnverifiedHeader(signed *cryptopb.SignedMessage) (*Header, error) {
	hdr, _, err := extractHeaderAndBody(signed)
	return hdr, err
}

func extractHeaderAndBody(signed *cryptopb.SignedMessage) (*Header, []byte, error) {
	var hdrAndBody cryptopb.HeaderAndBodyInternal
	if err := proto.Unmarshal(signed.HeaderAndBody, &hdrAndBody); err != nil {
		return nil, nil, err
	}
	var hdr cryptopb.Header
	if err := proto.Unmarshal(hdrAndBody.Header, &hdr); err != nil {
		return nil, nil, err
	}
	var ts time.Time
	if hdr.Timestamp != nil {
		var err error
		if ts, err = ptypes.Timestamp(hdr.Timestamp); err != nil {
			return nil, nil, err
		}
	}
	return &Header{
		SignatureAlgorithm: signatureAlgorithmFromPB(hdr.SignatureAlgorithm),
		VerificationKeyID:  hdr.VerificationKeyId,
		Timestamp:          ts,
		Metadata:           hdr.Metadata,
	}, hdrAndBody.Body, nil
}
