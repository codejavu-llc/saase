package services

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AmplitudePayload struct {
	OrgURL string `json:"orgUrl"`
}

type AmplitudeResponse struct {
	OrgID interface{} `json:"org_id"`
}

func CheckAmplitude(domain string, proxyURL string) bool {
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

	organizationName := domain
	if dotIdx := strings.Index(domain, "."); dotIdx != -1 {
		organizationName = domain[:dotIdx]
	}

	payload := AmplitudePayload{
		OrgURL: organizationName,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Amplitude payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://app.amplitude.com/d/config/login", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Amplitude request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.amplitude.com")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Amplitude request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Amplitude request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Amplitude response body: %v\n", err)
		return false
	}

	var amplitudeResp AmplitudeResponse
	if err := json.Unmarshal(bodyBytes, &amplitudeResp); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response for Amplitude: %v\n", err)
		return false
	}

	if amplitudeResp.OrgID != nil {
		return true
	}

	return false
}
