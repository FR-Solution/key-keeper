package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"go.uber.org/zap"
)

func (s *controller) rsa(i RSA) {
	crt, key, err := s.generateRSA()
	if err != nil {
		zap.L().Error("generate csr", zap.Error(err))
	}

	if err = s.storeRSA(i, crt, key); err != nil {
		zap.L().Error("store csr", zap.Error(err))
	}
}

func (s *controller) generateRSA() (private []byte, public []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	private = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	public = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(privateKey.Public().(*rsa.PublicKey)),
		},
	)
	return
}

func (s *controller) storeRSA(i RSA, private, public []byte) error {
	storedRSA := map[string]interface{}{
		"private": string(private),
		"public":  string(public),
	}
	if err := s.vault.Put(s.cfg.Keys.VaultKV, "rsa", storedRSA); err != nil {
		return fmt.Errorf("saving in vault: %w", err)
	}

	if err := s.storeKey(i.HostPath, private, public); err != nil {
		return fmt.Errorf("host path %s : %w", i.HostPath, err)
	}
	return nil
}
