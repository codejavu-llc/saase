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

type LinearVariables struct {
	Email     string `json:"email"`
	IsDesktop bool   `json:"isDesktop"`
	Type      string `json:"type"`
}

type LinearPayload struct {
	Query         string          `json:"query"`
	Variables     LinearVariables `json:"variables"`
	OperationName string          `json:"operationName"`
}

func generateRandomAlphabetStringLinear(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckLinear(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringLinear(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	queryStr := "query SsoUrlFromEmailQuery($email: String!, $isDesktop: Boolean, $type: IdentityProviderType!) {\n  ssoUrlFromEmail(email: $email, isDesktop: $isDesktop, type: $type) {\n    success\n    samlSsoUrl\n  }\n}"

	payload := LinearPayload{
		Query: queryStr,
		Variables: LinearVariables{
			Email:     email,
			IsDesktop: false,
			Type:      "general",
		},
		OperationName: "SsoUrlFromEmailQuery",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Linear payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://client-api.linear.app/graphql", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Linear request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Linear request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Linear request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Linear response body: %v\n", err)
		return false
	}

	if strings.Contains(string(bodyBytes), "samlSsoUrl") {
		return true
	}

	return false
}
