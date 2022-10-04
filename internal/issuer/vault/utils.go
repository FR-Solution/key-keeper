package vault

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"reflect"
)

func storeKeyPair(storePath string, name string, crt, key []byte) error {
	if err := os.MkdirAll(storePath, 0644); err != nil {
		return fmt.Errorf("mkdir all %s : %w", storePath, err)
	}

	if crt != nil {
		crtPath := path.Join(storePath, name+".pem")
		data, err := os.ReadFile(crtPath)
		if err != nil || !reflect.DeepEqual(crt, data) {
			if err := os.WriteFile(crtPath, crt, 0644); err != nil {
				return fmt.Errorf("failed to save certificate with path: %w", err)
			}
		}
	}

	if key != nil {
		keyPath := path.Join(storePath, name+"-key.pem")
		data, err := os.ReadFile(keyPath)
		if err != nil || !reflect.DeepEqual(key, data) {
			if err := os.WriteFile(keyPath, key, 0600); err != nil {
				return fmt.Errorf("failed to save key file: %w", err)
			}
		}
	}
	return nil
}

func readCertificate(path string, name string) (*x509.Certificate, error) {
	crt, err := os.ReadFile(path + "/" + name + ".pem")
	if err != nil {
		return nil, err
	}
	return parseCertificate(crt)
}

func parseCertificate(crt []byte) (*x509.Certificate, error) {
	pBlock, _ := pem.Decode(crt)
	return x509.ParseCertificate(pBlock.Bytes)
}

func writeToFile(filepath string, date []byte) error {
	dir := path.Dir(filepath)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return err
	}
	return os.WriteFile(filepath, date, 0644)
}
