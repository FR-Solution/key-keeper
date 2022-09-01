package resource

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/fraima/key-keeper/internal/config"
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

func createCSR(spec config.Spec) (crt, key []byte) {
	pk, _ := rsa.GenerateKey(rand.Reader, spec.PrivateKey.Size)

	template := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName:         spec.Subject.CommonName,
			Country:            spec.Subject.Country,
			Locality:           spec.Subject.Locality,
			Organization:       spec.Subject.Organization,
			OrganizationalUnit: spec.Subject.OrganizationalUnit,
			Province:           spec.Subject.Province,
			PostalCode:         spec.Subject.PostalCode,
			StreetAddress:      spec.Subject.StreetAddress,
			SerialNumber:       spec.Subject.SerialNumber,
		},
		IPAddresses:           getIPAddresses(spec.IPAddresses),
		URIs:                  getURLs(spec.Hostnames),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(spec.TTL),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	//Create certificate using templet
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk)

	//pem encoding of certificate
	crt = pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		},
	)

	key = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: derBytes,
		},
	)
	return
}

func getIPAddresses(ips []string) []net.IP {
	ipAddresses := make([]net.IP, 0, len(ips))

	for _, ip := range ips {
		ipAddresses = append(ipAddresses, net.IP(ip))
	}
	return ipAddresses
}

func getURLs(hostnames []string) []*url.URL {
	urls := make([]*url.URL, 0, len(hostnames))

	for _, hostname := range hostnames {
		// TODO: error handler
		url, _ := url.Parse(hostname)
		urls = append(urls, url)
	}
	return urls
}
