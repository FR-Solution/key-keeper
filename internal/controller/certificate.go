package controller

import (
	"fmt"
	"os"
)

func (s *controller) storeCertificate(path string, cert []byte) error {
	if err := os.WriteFile(path, cert, 0644); err != nil {
		return fmt.Errorf("failed to save certificate with path %s: %w", path, err)
	}
	return nil
}

func (s *controller) storeKey(path string, key []byte) error {
	if err := os.WriteFile(path, key, 0600); err != nil {
		return fmt.Errorf("failed to save key file: %w", err)
	}
	return nil
}

// func (s *controller) readCertificate(domain string) (*tls.Certificate, error) {
// 	crtContent, err := os.ReadFile(s.certPath)
// 	if err != nil {
// 		return nil, err
// 	}

// 	keyContent, err := os.ReadFile(s.keyPath)
// 	if err != nil {
// 		return nil, err
// 	}

// 	cert, err := tls.X509KeyPair(crtContent, keyContent)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse x509 key pair: %w", err)
// 	}
// 	if len(cert.Certificate) == 0 {
// 		return nil, fmt.Errorf("list of certificates is empty")
// 	}

// 	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &cert, nil
// }
