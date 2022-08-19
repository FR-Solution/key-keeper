package resource

import (
	"fmt"
	"path"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/controller"
)

func (s *resource) rootCA(i controller.RootCA) {
	isExist, err := s.isExistRootCA(i)
	if err != nil {
		zap.L().Warn(
			"existing root-ca",
			zap.String("common_name", i.CommonName),
			zap.Error(err),
		)
	}
	if isExist {
		return
	}

	if err := s.generateRootCA(i); err != nil {
		zap.L().Error(
			"generate root-ca",
			zap.String("common_name", i.CommonName),
			zap.Error(err),
		)
		return
	}
	zap.L().Info("root-ca generated", zap.String("common_name", i.CommonName))
}

func (s *resource) isExistRootCA(i controller.RootCA) (bool, error) {
	path := path.Join(i.RootPathCA, "cert/ca")
	rootCA, err := s.vault.Read(path)
	if err != nil {
		err = fmt.Errorf("read root CA: %w", err)
	}
	return rootCA != nil, err
}

func (s *resource) generateRootCA(i controller.RootCA) error {
	rootCAData := map[string]interface{}{
		"common_name": i.CommonName,
		"ttl":         "8760h",
	}
	path := path.Join(i.RootPathCA, "root/generate/internal")
	_, err := s.vault.Write(path, rootCAData)
	if err != nil {
		err = fmt.Errorf("create root CA: %w", err)
	}
	return err
}
