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

type GrammarlyPayload struct {
	Email string `json:"email"`
}

type GrammarlyResponse struct {
	LoginType string `json:"loginType"`
}

func generateRandomAlphabetStringGrammarly(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckGrammarly(domain string, proxyURL string) bool {
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

	req1, err := http.NewRequest("GET", "https://www.grammarly.com/signin", nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Grammarly request 1: %v\n", err)
		return false
	}
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Printf("Warning: Grammarly request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != 200 {
		fmt.Printf("Warning: Grammarly request 1 returned unexpected status code: %d\n", resp1.StatusCode)
		return false
	}

	var grauth, csrfToken string
	for _, cookie := range resp1.Cookies() {
		if cookie.Name == "grauth" {
			grauth = cookie.Value
		} else if cookie.Name == "csrf-token" {
			csrfToken = cookie.Value
		}
	}

	if grauth == "" || csrfToken == "" {
		fmt.Println("Warning: Could not find required cookies (grauth or csrf-token) in Grammarly response")
		return false
	}

	time.Sleep(5 * time.Second)

	randomValue := generateRandomAlphabetStringGrammarly(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	payload := GrammarlyPayload{
		Email: email,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Grammarly payload: %v\n", err)
		return false
	}

	req2, err := http.NewRequest("POST", "https://auth.grammarly.com/auth/v3/auth/info", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Grammarly request 2: %v\n", err)
		return false
	}

	req2.Header.Set("Cookie", fmt.Sprintf("grauth=%s; csrf-token=%s", grauth, csrfToken))
	req2.Header.Set("X-Csrf-Token", csrfToken)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: Grammarly request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		fmt.Printf("Warning: Grammarly request 2 returned unexpected status code: %d\n", resp2.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp2.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Grammarly response 2 body: %v\n", err)
		return false
	}

	var grammarlyResp GrammarlyResponse
	if err := json.Unmarshal(bodyBytes, &grammarlyResp); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response for Grammarly (unexpected body structure): %v\n", err)
		return false
	}

	if strings.ToUpper(grammarlyResp.LoginType) == "NONE" {
		return false
	}

	return true
}
