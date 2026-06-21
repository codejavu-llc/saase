package services

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func CheckDialpad(domain string, proxyURL string) bool {
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

	targetURL := fmt.Sprintf("https://dialpad.com/saml/login/okta/%s", domain)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Dialpad request: %v\n", err)
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Dialpad request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if location == "https://dialpad.com/auth/saml/request?error=BAD_SAML_CONFIG" {
		return false
	}

	return true
}
