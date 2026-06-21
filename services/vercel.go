package services

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func CheckVercel(domain string, proxyURL string) bool {
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

	targetURL := fmt.Sprintf("https://vercel.com/api/auth/sso?for=vercel&mode=login&next=https%%3A%%2F%%2Fvercel.com%%2Foauth%%2Fgit%%3FloginType%%3Dsaml%%26next%%3D%%252F%s123&teamId=%s", organizationName, organizationName)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Vercel request: %v\n", err)
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Vercel request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if strings.Contains(location, "team_not_found") {
		return false
	}

	return true
}
