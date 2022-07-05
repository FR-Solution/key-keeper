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
			zap.Error(err),
		)
		private, public, err = s.generateRSA()
		if err != nil {
			zap.L().Error(
				"generate rsa",
				zap.String("name", i.Name),
				zap.Error(err),
			)
			return
		}
		zap.L().Debug("rsa is created", zap.String("name", i.Name))
		storedRSA := map[string]interface{}{
			"private": string(private),
			"public":  string(public),
		}

		if err := s.vault.Put(s.cfg.Keys.VaultKV, i.Name, storedRSA); err != nil {
			zap.L().Error(
				"store rsa in kv",
				zap.String("name", i.Name),
				zap.String("kv", s.cfg.Keys.VaultKV),
				zap.Error(err),
			)
			return
		}
	} else {
		zap.L().Debug("rsa is read", zap.String("name", i.Name))
	}

	if err := s.storeKey(i.HostPath, private, public); err != nil {
		zap.L().Error(
			"store rsa in host",
			zap.String("name", i.Name),
			zap.String("path", i.HostPath),
			zap.Error(err),
		)
		return
	}
	zap.L().Debug("rsa is stored", zap.String("name", i.Name))
}

func (s *controller) readRSA(i RSA) (private []byte, public []byte, err error) {
	storedRSA, err := s.vault.Get(s.cfg.Keys.VaultKV, i.Name)
	if err != nil {
		err = fmt.Errorf("get from vault_kv %s : %w", s.cfg.Keys.VaultKV, err)
		return
	}

	private, public = []byte(storedRSA["private"].(string)), []byte(storedRSA["public"].(string))
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
