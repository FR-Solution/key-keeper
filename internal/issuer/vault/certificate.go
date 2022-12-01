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

func (s *vault) ensureCertificate(cert config.Certificate) {
	logger := zap.L().With(zap.String("resource_type", "certificate"), zap.String("name", cert.Name))

	err := checkCertificate(cert, logger)
	if err == nil {
		return
	}
	zap.L().Warn("ensure", zap.Error(err))

	if os.IsNotExist(err) || cert.WithUpdate {
		crt, key, err := s.generateCertificate(cert.Spec)
		if err != nil {
			zap.L().Error("generate", zap.Error(err))
		}

		err = storeKeyPair(cert.HostPath, cert.Name, crt, key)
		if err != nil {
			zap.L().Error("store", zap.Error(err))
			return
		}

		trigger(cert.Trigger, logger)
		zap.L().Debug("generated")
	}
}

func (s *vault) generateCertificate(certSpec config.Spec) ([]byte, []byte, error) {
	csr, key, err := s.createCSR(certSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("create csr: %w", err)
	}

	certData := map[string]interface{}{
		"csr": string(csr),
		"ttl": certSpec.TTL,
	}

	vaultPath := path.Join(s.caPath, "sign", s.role)
	cert, err := s.cli.Write(vaultPath, certData)
	if err != nil {
		return nil, nil, fmt.Errorf("generate with vault path %s : %w", vaultPath, err)
	}

	if crt, ok := cert["certificate"]; ok {
		return []byte(crt.(string)), key, nil
	}

	return nil, nil, fmt.Errorf("certificate block not found")
}

func (s *vault) createCSR(spec config.Spec) (crt, key []byte, err error) {
	pk, err := rsa.GenerateKey(rand.Reader, spec.PrivateKey.Size)
	if err != nil {
		err = fmt.Errorf("generate key: %w", err)
		return
	}

	commonName, err := getCommonName(spec.Subject.CommonName)
	if err != nil {
		err = fmt.Errorf("get common name: %w", err)
		return
	}

	ips, err := getIPAddresses(spec.IPAddresses)
	if err != nil {
		err = fmt.Errorf("get ip addresses: %w", err)
		return
	}

	dnsNames, err := getDNSNames(spec.Hostnames)
	if err != nil {
		err = fmt.Errorf("get hostname: %w", err)
		return
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         commonName,
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
		DNSNames:           dnsNames,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, pk)
	if err != nil {
		err = fmt.Errorf("create request: %w", err)
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

func getCommonName(src string) (string, error) {
	hostname, err := os.Hostname()
	return strings.ReplaceAll(src, "$HOSTNAME", hostname), err
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

func getDNSNames(src []string) ([]string, error) {
	var err error
	for i, hostname := range src {
		if hostname == "$HOSTNAME" {
			src[i], err = os.Hostname()
			break
		}
	}
	return src, err
}

func inSlice(str string, sl []string) bool {
	for _, s := range sl {
		if regexp.MustCompile(s).MatchString(str) {
			return true
		}
	}
	return false
}

func checkCertificate(cert config.Certificate, l *zap.Logger) error {
	crt, err := readCertificate(cert.HostPath, cert.Name)
	if crt != nil {
		if time.Until(crt.NotAfter) <= cert.RenewBefore {
			err = fmt.Errorf("expired until(h) %f", time.Until(crt.NotAfter).Hours())
		}
	}
	return err
}

func trigger(trigger [][]string, logger *zap.Logger) {
	for _, command := range trigger {
		var err error
		if len(command) == 1 {
			err = exec.Command(command[0]).Run()
		} else {
			err = exec.Command(command[0], command[1:]...).Run()
		}

		if err != nil {
			logger.Error("trigger", zap.Strings("command", command), zap.Error(err))
			continue
		}
		logger.Debug("trigger", zap.Strings("command", command))
	}
}
