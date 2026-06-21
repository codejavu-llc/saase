package services

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

type NotionPayload struct {
	Email            string `json:"email"`
	SamlCsrfNonce    string `json:"samlCsrfNonce"`
	LoginRouteOrigin string `json:"loginRouteOrigin"`
	AppSource        string `json:"appSource"`
}

func generateRandomAlphabetStringNotion(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckNotion(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringNotion(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	payload := NotionPayload{
		Email:            email,
		SamlCsrfNonce:    "e1cd9092-0a91-42a3-aa47-ab2761ce40aa",
		LoginRouteOrigin: "login",
		AppSource:        "notion",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Notion payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://app.notion.com/api/v3/getSamlRedirect", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Notion request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Notion request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 400 {
		return false
	}

	return true
}
