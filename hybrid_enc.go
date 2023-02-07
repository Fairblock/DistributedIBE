package tlock

import (
	//"bufio"
	//"crypto/sha256"
	//"errors"
	"fmt"
	"io"

	"crypto/rand"

	//"filippo.io/age"
	//"github.com/drand/drand/chain"
	//"github.com/drand/drand/common/scheme"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	// bls "github.com/drand/kyber-bls12381"
	// "github.com/drand/kyber/encrypt/ibe"
)

const fileKeySize = 16
const streamNonceSize = 16

func Encrypt(pk kyber.Point, id []byte , dst io.Writer, src io.Reader) (err error) {
	
	w, err := Encrypt2(pk, id, dst)
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

func Encrypt2(pk kyber.Point, id []byte,dst io.Writer) (io.WriteCloser, error) {


	fileKey := make([]byte, fileKeySize)
	if _, err := rand.Read(fileKey); err != nil {
		return nil, err
	}

	hdr := &Header{}

		stanzas, err := Wrap(pk,fileKey,id)
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

func Wrap(pk kyber.Point,fileKey []byte, id []byte) ([]*Stanza, error) {
	ciphertext, err := TimeLock(pk, id, fileKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt dek: %w", err)
	}

	body, err := CiphertextToBytes(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("bytes: %w", err)
	}

	stanza := Stanza{
		Type: "tlock",
		
		Body: body,
	}

	return []*Stanza{&stanza}, nil
}

func TimeLock(publicKey kyber.Point, id []byte, data []byte) (*Ciphertext, error) {
	if publicKey.Equal(publicKey.Null()) {
		return nil, fmt.Errorf("ErrInvalidPublicKey")
	}
	
	cipherText, err := EncryptIBE(bls.NewBLS12381Suite(), publicKey, id, data)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	return cipherText, nil
}

const (
	kyberPointLen = 48
	cipherVLen    = 16
	cipherWLen    = 16
)

// CiphertextToBytes converts a ciphertext value to a set of bytes.
func CiphertextToBytes(ciphertext *Ciphertext) ([]byte, error) {
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
