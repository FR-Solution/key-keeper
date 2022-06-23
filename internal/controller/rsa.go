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
	private, public, err := s.readRSA(i)
	if err != nil {
		zap.L().Warn(
			"read rsa",
			zap.String("name", i.Name),
			zap.Error(err))
		private, public, err = s.generateRSA()
		if err != nil {
			zap.L().Error(
				"generate rsa",
				zap.String("name", i.Name),
				zap.Error(err))
			return
		}
	}

	if err = s.storeRSA(i, private, public); err != nil {
		zap.L().Error(
			"store rsa",
			zap.String("name", i.Name),
			zap.Error(err),
		)
	}
}

func (s *controller) readRSA(i RSA) (private []byte, public []byte, err error) {
	storedRSA, err := s.vault.Get(s.cfg.Keys.VaultKV, i.Name)
	if err != nil {
		err = fmt.Errorf("get from vault_kv %s : %w", s.cfg.Keys.VaultKV, err)
		return
	}

	private, public = []byte(storedRSA["certificate"].(string)), []byte(storedRSA["private_key"].(string))
	return
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

	if err := s.vault.Put(s.cfg.Keys.VaultKV, i.Name, storedRSA); err != nil {
		return fmt.Errorf("saving in vault: %w", err)
	}

	if err := s.storeKey(i.HostPath, private, public); err != nil {
		return fmt.Errorf("host path %s : %w", i.HostPath, err)
	}
	return nil
}
