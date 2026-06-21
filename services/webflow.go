package services

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func generateRandomAlphabetStringWebflow(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckWebflow(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringWebflow(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)
	escapedEmail := url.QueryEscape(email)

	reqURL := fmt.Sprintf("https://webflow.com/sso/login?email=%s", escapedEmail)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Webflow request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Webflow request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 302 && resp.StatusCode != 301 && resp.StatusCode != 303 && resp.StatusCode != 307 {
		if resp.StatusCode != 200 {
			fmt.Printf("Warning: Webflow request returned unexpected status code: %d\n", resp.StatusCode)
		}
		return false
	}

	location := resp.Header.Get("Location")
	if location == "" {
		fmt.Println("Warning: Webflow response missing Location header")
		return false
	}

	if strings.Contains(location, "https://api.workos.com/sso/authorize") {
		return true
	}

	return false
}
