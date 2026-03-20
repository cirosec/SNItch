package helpers

import (
	"bufio"
	"os"
)

func ParseListFile(path string) ([]string, error) {
	res := make([]string, 0)
	if path == "" {
		return []string{}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		t := scanner.Text()
		if len(t) != 0 {
			res = append(res, t)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return res, nil
}
