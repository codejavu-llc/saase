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

type SmartsheetPayload struct {
	EmailAddress string `json:"emailAddress"`
}

type SmartsheetMethod struct {
	Type     string `json:"type"`
	Provider string `json:"provider"`
}

type SmartsheetResponse struct {
	AvailableMethods []SmartsheetMethod `json:"availableMethods"`
}

func generateRandomAlphabetStringSmartsheet(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckSmartsheet(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringSmartsheet(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	payload := SmartsheetPayload{
		EmailAddress: email,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Smartsheet payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://app.smartsheet.com/login/api/auth/options", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Smartsheet request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Smartsheet request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Smartsheet request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Smartsheet response body: %v\n", err)
		return false
	}

	var smartsheetResp SmartsheetResponse
	if err := json.Unmarshal(bodyBytes, &smartsheetResp); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response for Smartsheet (unexpected body structure): %v\n", err)
		return false
	}

	for _, method := range smartsheetResp.AvailableMethods {
		if strings.ToUpper(method.Type) == "SAML" || strings.ToUpper(method.Provider) == "SAML" {
			return true
		}
	}

	return false
}
