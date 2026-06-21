package services

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

func generateRandomAlphabetStringAtlassian(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckAtlassian(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringAtlassian(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)
	escapedEmail := url.QueryEscape(email)

	reqURL := fmt.Sprintf("https://id.atlassian.com/rest/login/state?continue=https%%3A%%2F%%2Fwww.atlassian.com%%2Fgateway%%2Fapi%%2Fstart%%2Fauthredirect%%3Fcontinue%%3Dhttps%%3A%%2F%%2Fwww.atlassian.com%%2F&application=wac--ic&email=%s", escapedEmail)
	
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Atlassian request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Referer", "https://id.atlassian.com/login")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Atlassian request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Atlassian request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Atlassian response body: %v\n", err)
		return false
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &rawMap); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response for Atlassian (unexpected body structure): %v\n", err)
		return false
	}

	_, hasRedirectTo := rawMap["redirectTo"]
	if hasRedirectTo && len(rawMap) == 1 {
		return true
	}

	return false
}
