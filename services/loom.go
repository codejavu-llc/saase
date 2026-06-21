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

type LoomVariables struct {
	Email         string `json:"email"`
	SsoOnly       bool   `json:"ssoOnly"`
	RequestSource string `json:"requestSource"`
}

type LoomPayload struct {
	OperationName string        `json:"operationName"`
	Variables     LoomVariables `json:"variables"`
	Query         string        `json:"query"`
}

type LoomResponse struct {
	Data struct {
		Response struct {
			Typename    string `json:"__typename"`
			AuthType    string `json:"authType"`
			RedirectURI string `json:"redirectUri"`
			Message     string `json:"message,omitempty"`
		} `json:"response"`
	} `json:"data"`
}

func generateRandomAlphabetStringLoom(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckLoom(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringLoom(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	queryStr := "query GetPrimaryAuthTypeForEmail($email: String!, $ssoOnly: Boolean, $requestSource: String) {\n  response: getPrimaryAuthTypeForEmail(\n    email: $email\n    ssoOnly: $ssoOnly\n    requestSource: $requestSource\n  ) {\n    __typename\n    ... on GetPrimaryAuthTypePayload {\n      authType\n      redirectUri\n      __typename\n    }\n    ... on Error {\n      message\n      __typename\n    }\n  }\n}"

	payload := LoomPayload{
		OperationName: "GetPrimaryAuthTypeForEmail",
		Variables: LoomVariables{
			Email:         email,
			SsoOnly:       true,
			RequestSource: "smartLogin",
		},
		Query: queryStr,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Loom payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://www.loom.com/graphql", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Loom request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Loom request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Loom request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Loom response body: %v\n", err)
		return false
	}

	var loomResp LoomResponse
	if err := json.Unmarshal(bodyBytes, &loomResp); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response for Loom (unexpected body structure): %v\n", err)
		return false
	}

	if loomResp.Data.Response.RedirectURI == "https://www.loom.com/signup" {
		return false
	}

	return true
}
