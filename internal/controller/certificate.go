package controller

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func (s *controller) storeCertificate(domain string, cert, key []byte) error {
	err := os.WriteFile(s.certPath, cert, 0644)
	if err != nil {
		return fmt.Errorf("failed to save certificate for domain %s: %w", domain, err)
	}

	err = os.WriteFile(s.keyPath, key, 0600)
	if err != nil {
		return fmt.Errorf("failed to save key file: %w", err)
	}

	return nil
}

func (s *controller) readCertificate(domain string) (*tls.Certificate, error) {
	crtContent, err := os.ReadFile(s.certPath)
	if err != nil {
		return nil, err
	}

	keyContent, err := os.ReadFile(s.keyPath)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(crtContent, keyContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 key pair: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("list of certificates is empty")
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
