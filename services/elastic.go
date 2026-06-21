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

type ElasticPayload struct {
	Email string `json:"email"`
}

type ElasticIdp struct {
	OrganizationName string `json:"organization_name"`
	LoginIdentifier  string `json:"login_identifier"`
}

type ElasticResponse struct {
	Idps []ElasticIdp `json:"idps"`
}

func generateRandomAlphabetStringElastic(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckElastic(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringElastic(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	payload := ElasticPayload{
		Email: email,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Elastic payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://cloud.elastic.co/api/v1/saas/auth/sso/_find_idp", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Elastic request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Elastic request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Elastic request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Elastic response body: %v\n", err)
		return false
	}

	var elasticResp ElasticResponse
	if err := json.Unmarshal(bodyBytes, &elasticResp); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response for Elastic: %v\n", err)
		return false
	}

	if len(elasticResp.Idps) > 0 {
		return true
	}

	return false
}
