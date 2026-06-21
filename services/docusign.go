package services

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func generateRandomAlphabetStringDocusign(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckDocusign(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringDocusign(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	data1 := url.Values{}
	data1.Set("email", email)

	req1, err := http.NewRequest("POST", "https://account.docusign.com/username", strings.NewReader(data1.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create DocuSign request 1: %v\n", err)
		return false
	}

	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Printf("Warning: DocuSign request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp1.Body.Close()

	var tokenValue string
	for _, cookie := range resp1.Cookies() {
		if cookie.Name == "__RequestVerificationToken" {
			tokenValue = cookie.Value
			break
		}
	}

	if tokenValue == "" {
		return false
	}

	data2 := url.Values{}
	data2.Set("email", email)
	data2.Set("__RequestVerificationToken", tokenValue)

	req2, err := http.NewRequest("POST", "https://account.docusign.com/saml2/login/sp", strings.NewReader(data2.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create DocuSign request 2: %v\n", err)
		return false
	}

	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Cookie", fmt.Sprintf("dsla_f=1; __RequestVerificationToken=%s", tokenValue))
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: DocuSign request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	bodyBytes, err := io.ReadAll(resp2.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read DocuSign response 2 body: %v\n", err)
		return false
	}

	if strings.Contains(string(bodyBytes), "SAMLRequest") {
		return true
	}

	return false
}
