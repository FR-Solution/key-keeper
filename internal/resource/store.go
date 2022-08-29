package resource

import (
	"crypto/tls"
	"crypto/x509"
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

func (s *resource) storeCertificate(path string, crt, key []byte) error {
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

func (s *resource) readCertificate(path string) (*tls.Certificate, error) {
	crt, err := os.ReadFile(path + ".pem")
	if err != nil {
		return nil, err
	}

	key, err := os.ReadFile(path + "-key.pem")
	if err != nil {
		return nil, err
	}
	return parseToCert(crt, key)
}

func (s *resource) readCA(vaulPath string) (crt, key []byte, err error) {
	vaulPath = path.Join(vaulPath, "cert/ca_chain")
	ica, err := s.vault.Read(vaulPath)
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

// func (s *resource) readCA(cert config.Certificate) (crt, key []byte, err error) {
// 	storedICA, err := s.vault.Get(cert.Spec.CommonName + "-ca")
// 	if err != nil {
// 		err = fmt.Errorf("get from vault_kv : %w", err)
// 		return
// 	}


// }

func parseToCert(crt, key []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(crt, key)
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
