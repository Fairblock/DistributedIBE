package tlock

import (
	//"bufio"
	//"crypto/sha256"
	//"errors"
	"bufio"
	"errors"
	"fmt"
	"io"

	"crypto/hmac"
	//"crypto/rand"

	//"filippo.io/age"
	//"github.com/drand/drand/chain"
	//"github.com/drand/drand/common/scheme"
	"filippo.io/age/armor"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	//bls "github.com/drand/kyber-bls12381"
	// bls "github.com/drand/kyber-bls12381"
	// "github.com/drand/kyber/encrypt/ibe"
)

func Decrypt(pk kyber.Point, sk kyber.Point,dst io.Writer, src io.Reader) error {
	rr := bufio.NewReader(src)
	
	if start, _ := rr.Peek(len(armor.Header)); string(start) == armor.Header {
		src = armor.NewReader(rr)
	} else {
		src = rr
	}
	
	r, err := Decrypt2(pk,sk,src)
	if err != nil {
		return fmt.Errorf("age decrypt: %w", err)
	}
	
	if _, err := io.Copy(dst, r); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

func Decrypt2(pk kyber.Point, sk kyber.Point,src io.Reader) (io.Reader, error) {

	hdr, payload, err := Parse(src)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}

	stanzas := make([]*Stanza, 0, len(hdr.Recipients))
	for _, s := range hdr.Recipients {
		stanzas = append(stanzas, (*Stanza)(s))
	}

	var fileKey []byte
	
	fileKey, err = Unwrap(pk, sk , stanzas)
	


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

func Unwrap(pk kyber.Point, sk kyber.Point,stanzas []*Stanza) ([]byte, error) {
	if len(stanzas) != 1 {
		return nil, errors.New("check stanzas length: should be one")
	}

	stanza := stanzas[0]

	if stanza.Type != "tlock" {
		return nil, fmt.Errorf("check stanza type: wrong type")
	}

	ciphertext, err := BytesToCiphertext(stanza.Body)
	if err != nil {
		return nil, fmt.Errorf("parse cipher dek: %w", err)
	}

	
	fileKey, err := TimeUnlock(pk, sk , ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return fileKey, nil
}

func BytesToCiphertext(b []byte) (*Ciphertext, error) {
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

	ct := Ciphertext{
		U: &u,
		V: cipherV,
		W: cipherW,
	}

	return &ct, nil
}

func TimeUnlock(publicKey kyber.Point,signature kyber.Point , ciphertext *Ciphertext) ([]byte, error) {


	data, err := DecryptIBE(bls.NewBLS12381Suite(), signature, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return data, nil
}