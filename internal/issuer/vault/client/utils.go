package client

import (
	"os"
	"path"
)

func writeToFile(filepath string, date []byte) error {
	dir := path.Dir(filepath)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return err
	}
	return os.WriteFile(filepath, date, 0644)
}
