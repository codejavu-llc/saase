package services

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

func generateRandomAlphabetStringGoTo(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckGoTo(domain string, proxyURL string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyURL != "" {
		parsedURL, err := url.Parse(proxyURL)
		if err == nil {
			tr.Proxy = http.ProxyURL(parsedURL)
		}
	}

	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	randomValue := generateRandomAlphabetStringGoTo(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)
	escapedEmail := url.QueryEscape(email)

	reqURL := fmt.Sprintf("https://identity.goto.com/loginOptions?email=%s", escapedEmail)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create GoTo request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: GoTo request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: GoTo request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read GoTo response body: %v\n", err)
		return false
	}

	var loginOptions []string
	if err := json.Unmarshal(bodyBytes, &loginOptions); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response for GoTo (unexpected body structure): %v\n", err)
		return false
	}

	if len(loginOptions) == 1 && loginOptions[0] == "password" {
		return false
	}

	return true
}
