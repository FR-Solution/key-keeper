package resource

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
)

func (s *resource) storeKey(path string, privare, public []byte) error {
	if err := os.WriteFile(path+".pem", privare, 0600); err != nil {
		return fmt.Errorf("failed to save privare key with path %s: %w", path, err)
	}

	if err := os.WriteFile(path+".pub", public, 0600); err != nil {
		return fmt.Errorf("failed to public key file: %w", err)
	}
	return nil
}

func (s *resource) storeKeyPair(path string, crt, key []byte) error {
	if crt != nil {
		if err := os.WriteFile(path+".pem", crt, 0644); err != nil {
			return fmt.Errorf("failed to save certificate with path %s: %w", path, err)
		}
	}

	if key != nil {
		if err := os.WriteFile(path+"-key.pem", key, 0600); err != nil {
			return fmt.Errorf("failed to save key file: %w", err)
		}
	}
	return nil
}

func (s *resource) readCertificate(path string) (*x509.Certificate, error) {
	crt, err := os.ReadFile(path + ".pem")
	if err != nil {
		return nil, err
	}

	pBlock, _ := pem.Decode(crt)
	return x509.ParseCertificate(pBlock.Bytes)
}

func (s *resource) readCA(vaultPath string) (crt, key []byte, err error) {
	vaultPath = path.Join(vaultPath, "cert/ca_chain")
	ica, err := s.vault.Read(vaultPath)
	if ica != nil {
		if c, ok := ica["certificate"]; ok {
			crt = []byte(c.(string))
		}
		if k, ok := ica["private_key"]; ok {
			key = []byte(k.(string))
		}
	}
	return
}
