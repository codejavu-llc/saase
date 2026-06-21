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

type RallyData struct {
	Email           string `json:"email"`
	BrowserName     string `json:"browserName"`
	OsName          string `json:"osName"`
	RedirectBaseURI string `json:"redirectBaseUri"`
	CaptchaToken    string `json:"captchaToken"`
}

type RallyVariables struct {
	Data RallyData `json:"data"`
}

type RallyPayload struct {
	ID            string         `json:"id"`
	Query         string         `json:"query"`
	Variables     RallyVariables `json:"variables"`
	OperationName string         `json:"operationName"`
}

func generateRandomAlphabetStringRally(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckRallyUXR(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringRally(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	queryStr := "mutation useEmailLoginMutation(\n  $data: EmailLoginInput!\n) {\n  emailLogin(data: $data) {\n    type\n    authorizationUrl\n    error\n    errorMessage\n  }\n}\n"

	payload := RallyPayload{
		ID:    "useEmailLoginMutation",
		Query: queryStr,
		Variables: RallyVariables{
			Data: RallyData{
				Email:           email,
				BrowserName:     "Chrome",
				OsName:          "Linux",
				RedirectBaseURI: "https://app.rallyuxr.com",
				CaptchaToken:    "",
			},
		},
		OperationName: "useEmailLoginMutation",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Rally UXR payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://api.rallyuxr.com/graphql", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Rally UXR request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Rally UXR request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Rally UXR request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Rally UXR response body: %v\n", err)
		return false
	}

	bodyStr := string(bodyBytes)
	
	if strings.Contains(bodyStr, `"type":"ERROR"`) {
		return false
	}

	return true
}
