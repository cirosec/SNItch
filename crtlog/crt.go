package crtlog

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cirosec/snitch/helpers"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// crtMaxBodySize caps the crt.name response body to keep a hostile or
// misbehaving endpoint from exhausting memory.
const crtMaxBodySize = 5 << 20

var crtClient = &http.Client{Timeout: 30 * time.Second}

type crtNameEntry struct {
	Sub string `json:"sub"`
}

func requestCrtName(ctx context.Context, url string, userAgent string) ([]crtNameEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	helpers.SetUserAgent(req, userAgent)
	r, err := crtClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.name returned unexpected status %d", r.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, crtMaxBodySize))
	if err != nil {
		return nil, err
	}
	var entries []crtNameEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse crt.name response: %w", err)
	}
	return entries, nil
}

func GetCertificateHostnamesByQuery(ctx context.Context, query string, userAgent string) ([]string, error) {
	baseURL := "https://crt.name/v1/search"
	params := url.Values{}
	params.Set("apex", query)
	params.Set("format", "json")

	requestURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())
	entries, err := requestCrtName(ctx, requestURL, userAgent)
	if err != nil {
		return nil, err
	}
	hostnames := []string{}
	for _, entry := range entries {
		hostnames = append(hostnames, entry.Sub)
	}
	cleanedHostnames := []string{}
	for _, h := range helpers.RemoveDuplicate(hostnames) {
		if !(strings.Contains(h, " ") || strings.Contains(h, "@")) {
			cleanedHostnames = append(cleanedHostnames, h)
		}
	}
	return cleanedHostnames, nil
}
