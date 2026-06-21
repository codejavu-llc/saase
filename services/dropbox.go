package services

import (
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

type DropboxResponse struct {
	UserSSOState string `json:"user_sso_state"`
}

func generateRandomAlphabetStringDropbox(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckDropbox(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringDropbox(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	data := url.Values{}
	data.Set("is_xhr", "true")
	data.Set("t", "")
	data.Set("email", email)

	req, err := http.NewRequest("POST", "https://www.dropbox.com/sso_state", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create Dropbox request: %v\n", err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Dropbox request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Dropbox request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Dropbox response body: %v\n", err)
		return false
	}

	var dropboxResp DropboxResponse
	if err := json.Unmarshal(bodyBytes, &dropboxResp); err != nil {
		fmt.Printf("Warning: Failed to parse JSON response for Dropbox (unexpected body structure): %v\n", err)
		return false
	}

	if dropboxResp.UserSSOState == "none" {
		return false
	}

	return true
}
