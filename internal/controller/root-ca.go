package controller

import (
	"fmt"

	"go.uber.org/zap"
)

func (s *controller) rootCA(i RootCA) {
	isExist, err := s.isExistRootCA(i)
	if err != nil {
		zap.L().Error(
			"generate root-ca",
			zap.Error(err),
		)
	}

	if isExist {
		return
	}

	if err := s.generateRootCA(i); err != nil {
		zap.L().Error(
			"generate root-ca",
			zap.Error(err),
		)
	}
}

func (s *controller) isExistRootCA(i RootCA) (bool, error) {
	path := i.RootPathCA + "/cert/ca"
	rootCA, err := s.vault.Read(path)
	if err != nil {
		err = fmt.Errorf("create root CA: %w", err)
	} else {
		zap.L().Info("root-ca generated", zap.String("common_name", i.CommonName))
	}
	return rootCA == nil, err
}

func (s *controller) generateRootCA(i RootCA) error {
	// create intermediate CA
	rootCAData := map[string]interface{}{
		"common_name": i.CommonName,
		"ttl":         "8760h",
	}
	path := i.RootPathCA + "/root/generate/internal"
	_, err := s.vault.Write(path, rootCAData)
	if err != nil {
		err = fmt.Errorf("create root CA: %w", err)
	} else {
		zap.L().Info("root-ca generated", zap.String("common_name", i.CommonName))
	}
	return err
}
