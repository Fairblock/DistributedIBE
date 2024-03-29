// Copyright (c) 2022 drand team
// The license can be found at https://github.com/drand/tlock/blob/main/LICENSE-MIT and https://github.com/drand/tlock/blob/main/LICENSE-APACHE


package distIBE

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	ibe "github.com/drand/kyber/encrypt/ibe"
)

const (
	fileKeySize     = 32
	streamNonceSize = 16
)

func Encrypt(pk kyber.Point, id []byte, dst io.Writer, src io.Reader) (err error) {
	w, err := encrypt(pk, id, dst)
	if err != nil {
		return fmt.Errorf("age encrypt: %w", err)
	}

	defer func() {
		if err = w.Close(); err != nil {
			err = fmt.Errorf("close: %w", err)
		}
	}()

	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

func encrypt(pk kyber.Point, id []byte, dst io.Writer) (io.WriteCloser, error) {
	fileKey := make([]byte, fileKeySize)
	if _, err := rand.Read(fileKey); err != nil {
		return nil, err
	}

	hdr := &Header{}

	stanzas, err := wrap(pk, fileKey, id)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key for recipient : %v", err)
	}

	hdr.Recipients = append(hdr.Recipients, (*Stanza)(stanzas[0]))

	if mac, err := headerMAC(fileKey, hdr); err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %v", err)
	} else {
		hdr.MAC = mac
	}
	if err := hdr.Marshal(dst); err != nil {
		return nil, fmt.Errorf("failed to write header: %v", err)
	}

	nonce := make([]byte, streamNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if _, err := dst.Write(nonce); err != nil {
		return nil, fmt.Errorf("failed to write nonce: %v", err)
	}

	return NewWriter(streamKey(fileKey, nonce), dst)
}

func wrap(pk kyber.Point, fileKey []byte, id []byte) ([]*Stanza, error) {
	ciphertext, err := lock(pk, id, fileKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt dek: %w", err)
	}

	body, err := ciphertextToBytes(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("bytes: %w", err)
	}

	stanza := Stanza{
		Type: "distIBE",
		Body: body,
	}

	return []*Stanza{&stanza}, nil
}

func lock(publicKey kyber.Point, id []byte, data []byte) (*ibe.Ciphertext, error) {
	if publicKey.Equal(publicKey.Null()) {
		return nil, fmt.Errorf("ErrInvalidPublicKey")
	}

	cipherText, err := ibe.EncryptCCAonG1(bls.NewBLS12381Suite(), publicKey, id, data)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	return cipherText, nil
}

const (
	kyberPointLen = 48
	cipherVLen    = 32
	cipherWLen    = 32
)

// CiphertextToBytes converts a ciphertext value to a set of bytes.
func ciphertextToBytes(ciphertext *ibe.Ciphertext) ([]byte, error) {
	kyberPoint, err := ciphertext.U.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal kyber point: %w", err)
	}

	b := make([]byte, kyberPointLen+cipherVLen+cipherWLen)
	copy(b, kyberPoint)
	copy(b[kyberPointLen:], ciphertext.V)
	copy(b[kyberPointLen+cipherVLen:], ciphertext.W)

	return b, nil
}
