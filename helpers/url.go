package helpers

import "net/url"

// GetURLPath extracts the path and query from a URL string, stripping scheme and host.
// This is used to compare redirect URLs from catch-all servers that echo back the
// requested hostname but redirect to the same path.
func GetURLPath(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.RequestURI()
}
