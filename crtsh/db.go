package crtsh

import (
	"context"
	"strings"

	"github.com/rosedblabs/rosedb/v2"
)

type CertSHDb struct {
	path string
	db   *rosedb.DB
}

func NewCRTSH(path string) *CertSHDb {

	options := rosedb.DefaultOptions
	options.DirPath = path
	db, err := rosedb.Open(options)
	if err != nil {
		panic(err)
	}
	return &CertSHDb{db: db, path: path}
}

func (c *CertSHDb) Close() {
	c.db.Close()
}

func (c *CertSHDb) Get(ctx context.Context, hostname string, userAgent string) ([]string, error) {
	hostname = strings.ToLower(hostname)
	val, err := c.db.Get([]byte(hostname))
	if err == nil {
		return strings.Split(string(val), ","), nil
	}
	certs, err := GetCertificateHostnamesByQuery(ctx, hostname, userAgent)
	if err != nil {
		return []string{}, err
	}
	err = c.db.Put([]byte(hostname), []byte(strings.Join(certs, ",")))
	if err != nil {
		return []string{}, err
	}
	return certs, nil
}
