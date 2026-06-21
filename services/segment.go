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

type SegmentVariables struct {
	Email string `json:"email"`
}

type SegmentPayload struct {
	OperationName string           `json:"operationName"`
	Variables     SegmentVariables `json:"variables"`
	Query         string           `json:"query"`
}

type SegmentLoginSettings struct {
	IsSSOEnabled bool `json:"isSSOEnabled"`
}

type SegmentData struct {
	GetLoginSettings SegmentLoginSettings `json:"getLoginSettings"`
}

type SegmentResponse struct {
	Data SegmentData `json:"data"`
}

func generateRandomAlphabetStringSegment(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckSegment(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringSegment(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	queryStr := "query checkSSO($email: Email!) {\n  getLoginSettings(email: $email) {\n    isSSOEnabled\n    isSSORequired\n    isCodeRequired\n    isUnifiedIdentityEnabled\n    organizationId\n    __typename\n  }\n}\n"

	payload := SegmentPayload{
		OperationName: "checkSSO",
		Variables: SegmentVariables{
			Email: email,
		},
		Query: queryStr,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Segment payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://app.segment.com/gateway-api/graphql?operation=checkSSO", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Segment request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Segment request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Segment request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Segment response body: %v\n", err)
		return false
	}

	var segmentResp SegmentResponse
	if err := json.Unmarshal(bodyBytes, &segmentResp); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response for Segment: %v\n", err)
		return false
	}

	if segmentResp.Data.GetLoginSettings.IsSSOEnabled {
		return true
	}

	return false
}
