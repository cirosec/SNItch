package helpers

import (
	"bufio"
	"os"
	"strings"
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
		t := strings.TrimSpace(scanner.Text())
		// Allow blank lines and '#' comments in list files.
		if len(t) != 0 && !strings.HasPrefix(t, "#") {
			res = append(res, t)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return res, nil
}
