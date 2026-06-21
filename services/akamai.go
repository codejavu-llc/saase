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
	"time"
)

type AkamaiPayload struct {
	UsernameOrEmail string `json:"usernameOrEmail"`
}

type AkamaiIdp struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type AkamaiResponse struct {
	ExternalIdps []AkamaiIdp `json:"externalIdps"`
}

func generateRandomAlphabetStringAkamai(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckAkamai(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringAkamai(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	payload := AkamaiPayload{
		UsernameOrEmail: email,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Akamai payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://control.akamai.com/ids-sso/v1/discovery", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Akamai request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Akamai request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Akamai request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Akamai response body: %v\n", err)
		return false
	}

	var akamaiResp AkamaiResponse
	if err := json.Unmarshal(bodyBytes, &akamaiResp); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response for Akamai: %v\n", err)
		return false
	}

	if len(akamaiResp.ExternalIdps) > 0 {
		return true
	}

	return false
}
