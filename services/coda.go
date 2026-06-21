package services

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CodaPayload struct {
	Email string `json:"email"`
}

type CodaResponse struct {
	RedirectURL string `json:"redirectUrl"`
}

func generateRandomAlphabetStringCoda(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckCoda(domain string, proxyURL string) bool {
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

	req1, err := http.NewRequest("GET", "https://coda.io/api/initLoad", nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Coda request 1: %v\n", err)
		return false
	}
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Printf("Warning: Coda request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != 200 {
		fmt.Printf("Warning: Coda request 1 returned unexpected status code: %d\n", resp1.StatusCode)
		return false
	}

	var csrfToken string
	for _, cookie := range resp1.Cookies() {
		if cookie.Name == "csrf_token" {
			csrfToken = cookie.Value
			break
		}
	}

	if csrfToken == "" {
		fmt.Println("Warning: Could not find csrf_token cookie in Coda response")
		return false
	}

	time.Sleep(5 * time.Second)

	randomValue := generateRandomAlphabetStringCoda(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	payload := CodaPayload{
		Email: email,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Coda payload: %v\n", err)
		return false
	}

	req2, err := http.NewRequest("POST", "https://coda.io/auth/api/ssoLogin", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Coda request 2: %v\n", err)
		return false
	}

	req2.Header.Set("Cookie", fmt.Sprintf("csrf_token=%s", csrfToken))
	req2.Header.Set("X-Csrf-Token", csrfToken)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Origin", "https://coda.io")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: Coda request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		fmt.Printf("Warning: Coda request 2 returned unexpected status code: %d\n", resp2.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp2.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Coda response 2 body: %v\n", err)
		return false
	}

	var codaResp CodaResponse
	if err := json.Unmarshal(bodyBytes, &codaResp); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response for Coda (unexpected body structure): %v\n", err)
		return false
	}

	if strings.Contains(codaResp.RedirectURL, "/signin") {
		return false
	}

	return true
}
