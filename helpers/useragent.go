package helpers

import "net/http"

// DefaultUserAgent is the User-Agent sent on every outbound HTTP(S) request
// when the user does not override it via --user-agent. Go's default
// ("Go-http-client/1.1") is trivially fingerprintable and is blocked by some
// WAFs/CDNs, which would otherwise corrupt HTTP status and title results.
const DefaultUserAgent = "Mozilla/5.0 (compatible; SNItch/1.4; +https://github.com/cirosec/SNItch)"

// ResolveUserAgent returns the configured user agent, falling back to
// DefaultUserAgent when none was supplied.
func ResolveUserAgent(userAgent string) string {
	if userAgent != "" {
		return userAgent
	}
	return DefaultUserAgent
}

// SetUserAgent sets the User-Agent header on req to the resolved user agent.
// It always sets a non-empty value so that Go's fingerprintable default is
// never sent.
func SetUserAgent(req *http.Request, userAgent string) {
	req.Header.Set("User-Agent", ResolveUserAgent(userAgent))
}
