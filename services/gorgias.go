package services

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func CheckGorgias(domain string, proxyURL string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyURL != "" {
		parsedURL, err := url.Parse(proxyURL)
		if err == nil {
			tr.Proxy = http.ProxyURL(parsedURL)
		}
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	organizationName := domain
	if dotIdx := strings.Index(domain, "."); dotIdx != -1 {
		organizationName = domain[:dotIdx]
	}

	data := url.Values{}
	data.Set("account_domain", organizationName)

	req, err := http.NewRequest("POST", "https://accounts.gorgias.com/helpdesk-subdomain", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create Gorgias request: %v\n", err)
		return false
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Gorgias request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if strings.Contains(location, "error=Gorgias%20account%20not%20found.") {
		return false
	}

	return true
}
