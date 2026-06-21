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

type SketchVariables struct {
	TeamName string `json:"teamName"`
}

type SketchPayload struct {
	OperationName string          `json:"operationName"`
	Variables     SketchVariables `json:"variables"`
	Query         string          `json:"query"`
}

func CheckSketch(domain string, proxyURL string) bool {
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

	queryStr := "query getSsoStartUrl($teamName: String!) {\n  ssoStartUrl(teamName: $teamName) {\n    successful\n    errors {\n      ...UserError\n      __typename\n    }\n    url\n    __typename\n  }\n}\n\nfragment UserError on UserError {\n  message\n  code\n  extensions {\n    ...UserErrorExtensions\n    __typename\n  }\n  __typename\n}\n\nfragment UserErrorExtensions on UserErrorExtensions {\n  reason\n  __typename\n}\n"

	payload := SketchPayload{
		OperationName: "getSsoStartUrl",
		Variables: SketchVariables{
			TeamName: organizationName,
		},
		Query: queryStr,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Sketch payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://graphql.sketch.cloud/api", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Sketch request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Sketch request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Sketch request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Sketch response body: %v\n", err)
		return false
	}

	if strings.Contains(string(bodyBytes), "Team not found") {
		return false
	}

	return true
}
