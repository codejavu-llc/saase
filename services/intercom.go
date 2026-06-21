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
	"regexp"
	"strings"
	"time"
)

type IntercomPayload struct {
	Email string `json:"email"`
}

func generateRandomAlphabetStringIntercom(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckIntercom(domain string, proxyURL string) bool {
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

	req1, err := http.NewRequest("GET", "https://app.intercom.com/a/saml", nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Intercom request 1: %v\n", err)
		return false
	}
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Printf("Warning: Intercom request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp1.Body.Close()

	var sessionCookie string
	for _, cookie := range resp1.Cookies() {
		if cookie.Name == "_intercom_session" {
			sessionCookie = cookie.Value
			break
		}
	}

	bodyBytes1, err := io.ReadAll(resp1.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Intercom response 1 body: %v\n", err)
		return false
	}

	re := regexp.MustCompile(`<meta\s+name="csrf-token"\s+content="([^"]+)"`)
	matches := re.FindStringSubmatch(string(bodyBytes1))
	var csrfToken string
	if len(matches) > 1 {
		csrfToken = matches[1]
	}

	if sessionCookie == "" || csrfToken == "" {
		fmt.Println("Warning: Could not find required cookies or CSRF token for Intercom")
		return false
	}

	time.Sleep(5 * time.Second)

	randomValue := generateRandomAlphabetStringIntercom(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	payload := IntercomPayload{
		Email: email,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal Intercom payload: %v\n", err)
		return false
	}

	req2, err := http.NewRequest("POST", "https://app.intercom.com/ember/saml_auths", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create Intercom request 2: %v\n", err)
		return false
	}

	req2.Header.Set("Cookie", fmt.Sprintf("_intercom_session=%s", sessionCookie))
	req2.Header.Set("X-Csrf-Token", csrfToken)
	req2.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: Intercom request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	bodyBytes2, err := io.ReadAll(resp2.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Intercom response 2 body: %v\n", err)
		return false
	}

	if strings.Contains(string(bodyBytes2), "app_name") {
		return true
	}

	return false
}
