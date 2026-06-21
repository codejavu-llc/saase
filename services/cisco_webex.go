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

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

type ActivationResponse struct {
	SSO bool `json:"sso"`
}

type ActivationPayload struct {
	Email            string `json:"email"`
	ReqID            string `json:"reqId"`
	CountryCode      string `json:"countryCode"`
	TimeZone         string `json:"timeZone"`
	ConfirmationCode bool   `json:"confirmationCode"`
	SuppressEmail    bool   `json:"suppressEmail"`
}

func generateRandomAlphabetString(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckCiscoWebex(domain string, proxyURL string) bool {
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

	bodyStr := "grant_type=client_credentials&scope=webexsquare%3Aadmin%20webexsquare%3Aget_conversation%20Identity%3ASCIM&self_contained_token=true"
	req, err := http.NewRequest("POST", "https://idbroker.webex.com/idb/oauth2/v1/access_token", strings.NewReader(bodyStr))
	if err != nil {
		fmt.Printf("Warning: Failed to create request 1: %v\n", err)
		return false
	}

	req.Header.Set("Authorization", "Basic QzY0YWIwNDYzOWVlZmVlNDc5OGY1OGU3YmMzZmUwMWQ0NzE2MWJlMGQ5N2ZmMGQzMWUwNDBhNmZmZTY2ZDdmMGE6ZjQyNjFhMDFhNDExMWIzYjNiMTcxMDU4MzA3M2NhZTljZDcxMDQ1MTdlN2Y3ODgwMGM0M2QwMWVlYTEzMzc4Mg==")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Request 1 returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read response 1 body: %v\n", err)
		return false
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response 1 (unexpected body structure): %v\n", err)
		return false
	}

	if tokenResp.AccessToken == "" {
		fmt.Println("Warning: Response 1 parsed successfully but access_token is empty")
		return false
	}

	time.Sleep(5 * time.Second)

	randomValue := generateRandomAlphabetString(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	payload := ActivationPayload{
		Email:            email,
		ReqID:            "WEBCLIENT",
		CountryCode:      "KRD",
		TimeZone:         "Asia/Kurdistan",
		ConfirmationCode: true,
		SuppressEmail:    false,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal payload 2: %v\n", err)
		return false
	}

	req2, err := http.NewRequest("POST", "https://license-a.wbx2.com/license/api/v1/users/activations", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create request 2: %v\n", err)
		return false
	}

	req2.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: Request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	bodyBytes2, err := io.ReadAll(resp2.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read response 2 body: %v\n", err)
		return false
	}

	if strings.Contains(string(bodyBytes2), `"errorCode":400102`) {
		return true
	}

	if resp2.StatusCode != 200 {
		fmt.Printf("Warning: Request 2 returned unexpected status code: %d\n", resp2.StatusCode)
		return false
	}

	var actResp ActivationResponse
	if err := json.Unmarshal(bodyBytes2, &actResp); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response 2 (unexpected body structure): %v\n", err)
		return false
	}

	return actResp.SSO
}
