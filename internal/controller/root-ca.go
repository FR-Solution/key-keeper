package controller

import (
	"fmt"

	"go.uber.org/zap"
)

func (s *controller) rootCA(i RootCA) {
	if err := s.generateRootCA(i); err != nil {
		zap.L().Error(
			"generate root-ca",
			zap.Error(err),
		)
	}
}

func (s *controller) generateRootCA(i RootCA) (err error) {
	// create intermediate CA
	csrData := map[string]interface{}{
		"common_name": i.CommonName,
		"ttl":         "8760h",
	}

	path := i.RootPathCA + "/generate/internal"
	_, err = s.vault.Write(path, csrData)
	if err != nil {
		err = fmt.Errorf("create root CA: %w", err)
	} else {
		zap.L().Info("root-ca generated", zap.String("common_name", i.CommonName))
	}
	return
}
