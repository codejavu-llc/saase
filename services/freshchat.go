package services

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func CheckFreshchat(domain string, proxyURL string) bool {
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

	targetURL := fmt.Sprintf("https://%s.freshchat.com/app/public/user_info/v3", organizationName)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Freshchat request: %v\n", err)
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Freshchat request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Freshchat response body: %v\n", err)
		return false
	}

	if strings.Contains(string(bodyBytes), "api.freshworks.com") {
		return false
	}

	return true
}
