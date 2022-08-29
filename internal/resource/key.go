package resource

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *resource) checkKey(i config.Key) {
	private, public, err := s.readRSA(i)
	if err != nil {
		zap.L().Warn(
			"read rsa",
			zap.String("name", i.Name),
			zap.Error(err),
		)
		private, public, err = s.generateKey(i.PrivateKey)
		if err != nil {
			zap.L().Error(
				"generate rsa",
				zap.String("name", i.Name),
				zap.Error(err),
			)
			return
		}
		zap.L().Debug("rsa is created", zap.String("name", i.Name))

		if i.Public {
			storedRSA := map[string]interface{}{
				"private": string(private),
				"public":  string(public),
			}

			if err := s.vault.Put(i.Name, storedRSA); err != nil {
				zap.L().Error(
					"store rsa in kv",
					zap.String("name", i.Name),
					zap.Error(err),
				)
				return
			}
			zap.L().Debug("rsa is saved in kv", zap.String("name", i.Name))
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

func (s *resource) readRSA(i config.Key) (private []byte, public []byte, err error) {
	storedRSA, err := s.vault.Get(i.Name)
	if err != nil {
		err = fmt.Errorf("get from vault_kv : %w", err)
		return
	}

	private, public = []byte(storedRSA["private"].(string)), []byte(storedRSA["public"].(string))
	return
}

func (s *resource) generateKey(info config.PrivateKey) (private []byte, public []byte, err error) {
	if strings.ToLower(info.Algorithm) != "rsa" {
		err = fmt.Errorf("the algorithm %s is not supported", info.Algorithm)
		return
	}
	return s.generateRSA(info.Size)
}

func (s *resource) generateRSA(size int) (private []byte, public []byte, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return
	}

	private = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return
	}
	public = pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	return
}
