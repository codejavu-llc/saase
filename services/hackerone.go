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

func generateRandomAlphabetStringHackerOne(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckHackerOne(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringHackerOne(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)
	escapedEmail := url.QueryEscape(email)

	reqURL := fmt.Sprintf("https://hackerone.com/users/saml/sign_in?email=%s&remember_me=false", escapedEmail)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create HackerOne request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: HackerOne request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 302 && resp.StatusCode != 301 && resp.StatusCode != 303 && resp.StatusCode != 307 {
		if resp.StatusCode != 200 {
			fmt.Printf("Warning: HackerOne request returned unexpected status code: %d\n", resp.StatusCode)
		}
		return false
	}

	location := resp.Header.Get("Location")
	if location == "" {
		fmt.Println("Warning: HackerOne response missing Location header")
		return false
	}

	if location == "https://hackerone.com/users/sign_in" || strings.HasSuffix(location, "/users/sign_in") {
		return false
	}

	return true
}
