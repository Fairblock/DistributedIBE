package distIBE

import (
	"bufio"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"

	"filippo.io/age/armor"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
  ibe "github.com/drand/kyber/encrypt/ibe"
)

func Decrypt(pk kyber.Point, sk kyber.Point, dst io.Writer, src io.Reader) error {
	rr := bufio.NewReader(src)

	if start, _ := rr.Peek(len(armor.Header)); string(start) == armor.Header {
		src = armor.NewReader(rr)
	} else {
		src = rr
	}

	r, err := decrypt(pk, sk, src)
	if err != nil {
		return fmt.Errorf("age decrypt: %w", err)
	}

	if _, err := io.Copy(dst, r); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

func decrypt(pk kyber.Point, sk kyber.Point, src io.Reader) (io.Reader, error) {

	hdr, payload, err := Parse(src)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}

	stanzas := make([]*Stanza, 0, len(hdr.Recipients))
	for _, s := range hdr.Recipients {
		stanzas = append(stanzas, (*Stanza)(s))
	}

	var fileKey []byte

	fileKey, err = unwrap(pk, sk, stanzas)

	if fileKey == nil {
		return nil, fmt.Errorf("errNoMatch")
	}

	if mac, err := headerMAC(fileKey, hdr); err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %v", err)
	} else if !hmac.Equal(mac, hdr.MAC) {
		return nil, errors.New("bad header MAC")
	}

	nonce := make([]byte, streamNonceSize)
	if _, err := io.ReadFull(payload, nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %v", err)
	}

	return NewReader(streamKey(fileKey, nonce), payload)
}

func unwrap(pk kyber.Point, sk kyber.Point, stanzas []*Stanza) ([]byte, error) {
	if len(stanzas) != 1 {
		return nil, errors.New("check stanzas length: should be one")
	}

	stanza := stanzas[0]

	if stanza.Type != "distIBE" {
		return nil, fmt.Errorf("check stanza type: wrong type")
	}

	ciphertext, err := bytesToCiphertext(stanza.Body)
	if err != nil {
		return nil, fmt.Errorf("parse cipher dek: %w", err)
	}

	fileKey, err := unlock(pk, sk, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return fileKey, nil
}

func bytesToCiphertext(b []byte) (*ibe.Ciphertext, error) {
	expLen := kyberPointLen + cipherVLen + cipherWLen
	if len(b) != expLen {
		return nil, fmt.Errorf("incorrect length: exp: %d got: %d", expLen, len(b))
	}

	kyberPoint := make([]byte, kyberPointLen)
	copy(kyberPoint, b[:kyberPointLen])

	cipherV := make([]byte, cipherVLen)
	copy(cipherV, b[kyberPointLen:kyberPointLen+cipherVLen])

	cipherW := make([]byte, cipherVLen)
	copy(cipherW, b[kyberPointLen+cipherVLen:])

	var u bls.KyberG1
	if err := u.UnmarshalBinary(kyberPoint); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G1: %w", err)
	}

	ct := ibe.Ciphertext{
		U: &u,
		V: cipherV,
		W: cipherW,
	}

	return &ct, nil
}

func unlock(publicKey kyber.Point, signature kyber.Point, ciphertext *ibe.Ciphertext) ([]byte, error) {

	data, err := ibe.DecryptCCAonG1(bls.NewBLS12381Suite(), signature, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return data, nil
}
