package services

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func CheckGoogle(domain string, proxyURL string) bool {
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

	targetURL := fmt.Sprintf("https://www.google.com/a/%s/ServiceLogin", domain)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Google request: %v\n", err)
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Google request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 302 {
		return false
	}

	return true
}
