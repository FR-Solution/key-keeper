package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type config struct {
	dir string
	reg *regexp.Regexp

	oldConfig map[string]struct{}
}

func New(configDir, configNameLayout string) (*config, error) {
	reg, err := regexp.Compile(configNameLayout)
	if err != nil {
		return nil, err
	}

	return &config{
		dir: configDir,
		reg: reg,

		oldConfig: make(map[string]struct{}),
	}, nil
}

// GetNewConfig return new config from config dir.
func (s *config) GetNewConfig() (newCfg Config, err error) {
	list, err := s.getNewConfigFiles()
	if err != nil {
		return
	}

	for _, path := range list {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			zap.L().Error("read config file", zap.String("path", path), zap.Error(err))
			continue
		}
		var cfg Config
		if err = yaml.Unmarshal(data, cfg); err != nil {
			zap.L().Error("unmurshal config file", zap.String("path", path), zap.Error(err))
			continue
		}

		newCfg.Issueres = append(newCfg.Issueres, cfg.Issueres...)
		newCfg.Resource.Certificates = append(newCfg.Resource.Certificates, cfg.Resource.Certificates...)
		newCfg.Resource.Keys = append(newCfg.Resource.Keys, cfg.Resource.Keys...)
		s.oldConfig[path] = struct{}{}
	}

	return
}

func (s *config) getNewConfigFiles() ([]string, error) {
	var newConfigFiles []string
	err := filepath.Walk(s.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		_, isOld := s.oldConfig[path]
		if !isOld && !info.IsDir() && s.reg.Match([]byte(info.Name())) {
			newConfigFiles = append(newConfigFiles, path)
		}
		return nil
	})
	return newConfigFiles, err
}
