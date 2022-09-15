package vault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *vault) checkCertificate(certCfg config.Certificate) {
	cert, err := readCertificate(certCfg.HostPath, certCfg.Name)
	if cert != nil && time.Until(cert.NotAfter) > certCfg.RenewBefore {
		return
	}
	if err != nil && !os.IsNotExist(err) {
		zap.L().Error("read certificate", zap.String("path", certCfg.HostPath), zap.Error(err))
	}

	crt, key, err := s.generateCertificate(certCfg.Spec)
	if err != nil {
		zap.L().Error(
			"generate certificate",
			zap.String("name", certCfg.Name),
			zap.Error(err),
		)
	}

	if err = storeKeyPair(certCfg.HostPath, certCfg.Name, crt, key); err != nil {
		zap.L().Error(
			"store certificate",
			zap.String("name", certCfg.Name),
			zap.Error(err),
		)
		return
	}

	for _, command := range certCfg.Trigger {
		cmd := strings.Split(command, " ")
		err := exec.Command(cmd[0], cmd[1:]...).Run()
		zap.L().Error(
			"certificate trigger",
			zap.String("name", certCfg.Name),
			zap.String("command", command),
			zap.Error(err),
		)
	}
	zap.L().Info("certificate generated", zap.String("name", certCfg.Name))
}

func (s *vault) generateCertificate(certSpec config.Spec) ([]byte, []byte, error) {
	csr, key, err := createCSR(certSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("create csr: %w", err)
	}

	certData := map[string]interface{}{
		"csr": string(csr),
		"ttl": certSpec.TTL,
	}

	vaultPath := path.Join(s.caPath, "sign", s.role)
	cert, err := s.Write(vaultPath, certData)
	if err != nil {
		return nil, nil, fmt.Errorf("generate with vault path %s : %w", vaultPath, err)
	}

	if crt, ok := cert["certificate"]; ok {
		return []byte(crt.(string)), key, nil
	}

	return nil, nil, fmt.Errorf("certificate block not found")
}

func createCSR(spec config.Spec) (crt, key []byte, err error) {
	pk, err := rsa.GenerateKey(rand.Reader, spec.PrivateKey.Size)
	if err != nil {
		err = fmt.Errorf("generate key: %w", err)
		return
	}

	ips, err := getIPAddresses(spec.IPAddresses)
	if err != nil {
		err = fmt.Errorf("get ip addresses: %w", err)
		return
	}
	template := x509.CertificateRequest{
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
		IPAddresses:        ips,
		DNSNames:           spec.Hostnames,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, pk)
	if err != nil {
		err = fmt.Errorf("create certificate request: %w", err)
		return
	}

	crt = pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csr,
		},
	)
	key = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pk),
		},
	)
	return
}

func getIPAddresses(cfg config.IPAddresses) ([]net.IP, error) {
	ipAddresses := make(map[string]net.IP)

	for _, ip := range cfg.Static {
		netIP := net.ParseIP(ip)
		if netIP.To4() != nil {
			ipAddresses[ip] = netIP
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.New("get interfaces")
	}

	for _, i := range ifaces {
		if inSlice(i.Name, cfg.Interfaces) {
			addrs, err := i.Addrs()
			if err != nil {
				return nil, fmt.Errorf("get interface %s addresses", i.Name)
			}

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				if ip.To4() != nil {
					ipAddresses[ip.String()] = ip
				}
			}
		}
	}

	for _, h := range cfg.DNSLookup {
		ips, err := net.LookupIP(h)
		if err != nil {
			return nil, fmt.Errorf("lookup ip for %s ", h)
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				ipAddresses[ip.String()] = ip
			}
		}
	}

	r := make([]net.IP, 0, len(ipAddresses))
	for _, ip := range ipAddresses {
		r = append(r, ip)
	}
	return r, nil
}

func inSlice(str string, sl []string) bool {
	for _, s := range sl {
		if regexp.MustCompile(s).MatchString(str) {
			return true
		}
	}
	return false
}
