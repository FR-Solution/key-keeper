package vault

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func storeKeyPair(path string, name string, crt, key []byte) error {
	if err := os.MkdirAll(path, 0644); err != nil {
		return fmt.Errorf("mkdir all %s : %w", path, err)
	}

	if crt != nil {
		if err := os.WriteFile(path+"/"+name+".pem", crt, 0644); err != nil {
			return fmt.Errorf("failed to save certificate with path %s: %w", path, err)
		}
	}

	if key != nil {
		if err := os.WriteFile(path+"/"+name+"-key.pem", key, 0600); err != nil {
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

func writeToFile(path, date string) error {
	if err := os.MkdirAll(path, 0644); err != nil {
		return fmt.Errorf("mkdir all %s : %w", path, err)
	}
	return os.WriteFile(path, []byte(date), 0644)
}
