package services

import (
	"context"
	"net"
	"strings"
)

func CheckSalesforceSites(domain string, proxyURL string) bool {
	organizationName := domain
	if dotIdx := strings.Index(domain, "."); dotIdx != -1 {
		organizationName = domain[:dotIdx]
	}

	targetHost := organizationName + ".my.salesforce-sites.com"

	_, err := net.DefaultResolver.LookupHost(context.Background(), targetHost)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return false
		}
		return false
	}

	return true
}
