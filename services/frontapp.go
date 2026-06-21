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

func CheckFrontApp(domain string, proxyURL string) bool {
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

	// 1. Initial GET request to retrieve CSRF and session cookies
	req1, err := http.NewRequest("GET", "https://app.frontapp.com/signin", nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Frontapp request 1: %v\n", err)
		return false
	}
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Printf("Warning: Frontapp request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp1.Body.Close()

	var frontCsrf, frontId, frontIdSig string
	for _, cookie := range resp1.Cookies() {
		switch cookie.Name {
		case "front.csrf":
			frontCsrf = cookie.Value
		case "front.id":
			frontId = cookie.Value
		case "front.id.sig":
			frontIdSig = cookie.Value
		}
	}

	if frontCsrf == "" || frontId == "" || frontIdSig == "" {
		return false
	}

	// Format company/organization name from the domain
	organizationName := domain
	if dotIdx := strings.Index(domain, "."); dotIdx != -1 {
		organizationName = domain[:dotIdx]
	}

	// 2. POST request to check the company sign-in endpoint
	req2URL := fmt.Sprintf("https://app.frontapp.com/api/1/signin/%s", url.PathEscape(organizationName))
	req2, err := http.NewRequest("POST", req2URL, nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Frontapp request 2: %v\n", err)
		return false
	}

	// Construct Cookie header manually to mirror specified structure securely
	cookieHeader := fmt.Sprintf("front.id=%s; front.id.sig=%s; front.csrf=%s", frontId, frontIdSig, frontCsrf)
	req2.Header.Set("Cookie", cookieHeader)
	req2.Header.Set("X-Front-Xsrf", frontCsrf)
	req2.Header.Set("Content-Length", "0")
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: Frontapp request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	bodyBytes, err := io.ReadAll(resp2.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Frontapp response 2 body: %v\n", err)
		return false
	}

	if strings.Contains(string(bodyBytes), `"redirect_url"`) {
		return true
	}

	return false
}
