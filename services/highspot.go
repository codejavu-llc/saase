package services

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func generateRandomAlphabetStringHighspot(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckHighspot(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringHighspot(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	data := url.Values{}
	data.Set("email", email)
	data.Set("context", `{"office":null}`)
	data.Set("switchTo", "")

	req, err := http.NewRequest("POST", "https://app.highspot.com/signin", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create Highspot request: %v\n", err)
		return false
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Highspot request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 302 && resp.StatusCode != 301 && resp.StatusCode != 303 && resp.StatusCode != 307 {
		if resp.StatusCode != 200 {
			fmt.Printf("Warning: Highspot request returned unexpected status code: %d\n", resp.StatusCode)
		}
		return false
	}

	location := resp.Header.Get("Location")
	if location == "" {
		fmt.Println("Warning: Highspot response missing Location header")
		return false
	}

	if location == "https://app.highspot.com/signin" || strings.HasSuffix(location, "/signin") {
		return false
	}

	return true
}
