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

func generateRandomAlphabetStringQuip(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckQuip(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringQuip(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	data := url.Values{}
	data.Set("email", email)
	data.Set("_csrf", "test123")

	req, err := http.NewRequest("POST", "https://quip.com/account/login", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create Quip request: %v\n", err)
		return false
	}

	req.Header.Set("Cookie", "id=test123")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Quip request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 {
		return true
	}

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Quip request returned unexpected status code: %d\n", resp.StatusCode)
	}

	return false
}
