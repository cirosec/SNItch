package crtsh

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cirosec/snitch/helpers"
	"io"
	"net/http"
	"strings"
)

type crtCertificateInfo struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

func requestCrtsh(ctx context.Context, url string, userAgent string) ([]crtCertificateInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var certs []crtCertificateInfo
	if err := json.Unmarshal(body, &certs); err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh response: %w", err)
	}
	return certs, nil
}

func GetCertificateHostnamesByQuery(ctx context.Context, query string, userAgent string) ([]string, error) {
	baseURL := "https://crt.sh/"
	output := "json"

	url := fmt.Sprintf("%s?q=%s&output=%s", baseURL, query, output)
	certs, err := requestCrtsh(ctx, url, userAgent)
	if err != nil {
		return nil, err
	}
	hostnames := []string{}
	for _, cert := range certs {
		hostnames = append(hostnames, cert.CommonName)
		hostnames = append(hostnames, strings.Split(cert.NameValue, "\n")...)
	}
	cleanedHostnames := []string{}
	for _, h := range helpers.RemoveDuplicate(hostnames) {
		if !(strings.Contains(h, " ") || strings.Contains(h, "@")) {
			cleanedHostnames = append(cleanedHostnames, h)
		}
	}
	return cleanedHostnames, nil
}
