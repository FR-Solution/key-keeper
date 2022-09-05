package vault

import (
	"os"
)

func readFromFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func writeToFile(path, date string) error {
	return os.WriteFile(path, []byte(date), 0644)
}
