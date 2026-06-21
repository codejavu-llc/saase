package services

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type PostmanPayload struct {
	Team string `json:"team"`
}

func CheckPostman(domain string, proxyURL string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyURL != "" {
		parsedURL, err := url.Parse(proxyURL)
		if err == nil {
			tr.Proxy = http.ProxyURL(parsedURL)
		}
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req1, err := http.NewRequest("GET", "https://identity.getpostman.com/enterprise/login", nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Postman request 1: %v\n", err)
		return false
	}
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Printf("Warning: Postman request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp1.Body.Close()

	var legacySailsSid string
	for _, cookie := range resp1.Cookies() {
		if cookie.Name == "legacy_sails.sid" {
			legacySailsSid = cookie.Value
			break
		}
	}

	bodyBytes1, err := io.ReadAll(resp1.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Postman response 1 body: %v\n", err)
		return false
	}

	re := regexp.MustCompile(`name="csrfToken"\s+value="([^"]+)"`)
	matches := re.FindStringSubmatch(string(bodyBytes1))
	if len(matches) < 2 || legacySailsSid == "" {
		return false
	}
	csrfToken := matches[1]

	organizationName := domain
	if dotIdx := strings.Index(domain, "."); dotIdx != -1 {
		organizationName = domain[:dotIdx]
	}

	payload := PostmanPayload{
		Team: organizationName,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Postman payload: %v\n", err)
		return false
	}

	req2, err := http.NewRequest("POST", "https://identity.getpostman.com/auth/search", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Postman request 2: %v\n", err)
		return false
	}

	req2.Header.Set("Cookie", fmt.Sprintf("legacy_sails.sid=%s", legacySailsSid))
	req2.Header.Set("X-Csrf-Token", csrfToken)
	req2.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: Postman request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	bodyBytes2, err := io.ReadAll(resp2.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Postman response 2 body: %v\n", err)
		return false
	}

	if strings.Contains(string(bodyBytes2), "EntityNotFound") {
		return false
	}

	return true
}
