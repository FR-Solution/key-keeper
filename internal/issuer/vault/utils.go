package vault

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
)

func storeKeyPair(storePath string, name string, crt, key []byte) error {
	if err := os.MkdirAll(storePath, 0644); err != nil {
		return fmt.Errorf("mkdir all %s : %w", storePath, err)
	}

	if crt != nil {
		if err := os.WriteFile(path.Join(storePath, name+".pem"), crt, 0644); err != nil {
			return fmt.Errorf("failed to save certificate with path %s: %w", storePath, err)
		}
	}

	if key != nil {
		if err := os.WriteFile(path.Join(storePath, name+"-key.pem"), key, 0600); err != nil {
			return fmt.Errorf("failed to save key file: %w", err)
		}
	}
	return nil
}

func readCertificate(path string, name string) (*x509.Certificate, error) {
	crt, err := os.ReadFile(path + "/" + name + ".pem")
	if err != nil {
		return nil, err
	}

	pBlock, _ := pem.Decode(crt)
	return x509.ParseCertificate(pBlock.Bytes)
}

func readFromFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func writeToFile(filepath string, date []byte) error {
	dir := path.Dir(filepath)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return err
	}
	return os.WriteFile(filepath, date, 0644)
}
