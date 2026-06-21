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

type LogzioPayload struct {
	Email string `json:"email"`
}

func generateRandomAlphabetStringLogzio(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckLogzio(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringLogzio(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	payload := LogzioPayload{
		Email: email,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Logz.io payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://app.logz.io/auth/login/resolve-sso-connection", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Logz.io request: %v\n", err)
		return false
	}

	req.Header.Set("Cookie", "Logzio-Csrf=test535")
	req.Header.Set("X-Logz-Csrf-Token-V2", "test535")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Logz.io request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Logz.io response body: %v\n", err)
		return false
	}

	if strings.Contains(string(bodyBytes), "SSO/NOT_FOUND") {
		return false
	}

	return true
}
