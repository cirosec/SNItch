package crtlog

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/rosedblabs/rosedb/v2"
)

type CrtLogDb struct {
	path string
	db   *rosedb.DB
}

// NewCrtLog opens the rosedb-backed cache. When the database cannot be opened
// (e.g. an unwritable path), the scan degrades to a no-cache mode instead of
// crashing: every lookup then hits the network.
func NewCrtLog(path string) *CrtLogDb {

	options := rosedb.DefaultOptions
	options.DirPath = path
	db, err := rosedb.Open(options)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[crt.name] ⚠ failed to open cache db at %s (%v), continuing without cache\n", path, err)
		return &CrtLogDb{path: path}
	}
	return &CrtLogDb{db: db, path: path}
}

func (c *CrtLogDb) Close() {
	if c.db != nil {
		c.db.Close()
	}
}

func (c *CrtLogDb) Get(ctx context.Context, hostname string, userAgent string) ([]string, error) {
	hostname = strings.ToLower(hostname)
	if c.db != nil {
		val, err := c.db.Get([]byte(hostname))
		if err == nil {
			return strings.Split(string(val), ","), nil
		}
	}
	certs, err := GetCertificateHostnamesByQuery(ctx, hostname, userAgent)
	if err != nil {
		return []string{}, err
	}
	if c.db != nil {
		err = c.db.Put([]byte(hostname), []byte(strings.Join(certs, ",")))
		if err != nil {
			return []string{}, err
		}
	}
	return certs, nil
}
