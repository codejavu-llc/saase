// This service is shit, if the status was 403, you should manually visit the website, solve the antibot, its ip based
package services

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func generateRandomAlphabetStringAirtable(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckAirtable(domain string, proxyURL string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyURL != "" {
		parsedURL, err := url.Parse(proxyURL)
		if err == nil {
			tr.Proxy = http.ProxyURL(parsedURL)
		}
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create cookie jar for Airtable: %v\n", err)
		return false
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req1, err := http.NewRequest("GET", "https://airtable.com/sso/login", nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Airtable request 1: %v\n", err)
		return false
	}
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Printf("Warning: Airtable request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != 200 {
		fmt.Printf("Warning: Airtable request 1 returned unexpected status code: %d\n", resp1.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp1.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Airtable response 1 body: %v\n", err)
		return false
	}

	re := regexp.MustCompile(`name="_csrf"\s+value="([^"]+)"`)
	matches := re.FindStringSubmatch(string(bodyBytes))
	if len(matches) < 2 {
		fmt.Println("Warning: Could not extract CSRF token from Airtable response")
		return false
	}
	csrfToken := matches[1]

	time.Sleep(5 * time.Second)

	randomValue := generateRandomAlphabetStringAirtable(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	data := url.Values{}
	data.Set("_csrf", csrfToken)
	data.Set("shouldRedirectUnregisteredEmailToSignup", "1")
	data.Set("urlToRedirectTo", "")
	data.Set("countryCode", "")
	data.Set("didConsentToMarketing", "")
	data.Set("didConsentToDataEnrichment", "")
	data.Set("email", email)

	req2, err := http.NewRequest("POST", "https://airtable.com/auth/sso", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create Airtable request 2: %v\n", err)
		return false
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: Airtable request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 302 && resp2.StatusCode != 303 && resp2.StatusCode != 307 {
		fmt.Printf("Warning: Airtable request 2 did not return a redirect status code, got: %d\n", resp2.StatusCode)
		return false
	}

	location := resp2.Header.Get("Location")
	if location == "" {
		fmt.Println("Warning: Airtable response 2 missing Location header")
		return false
	}

	if location == "/sso/login" || strings.HasSuffix(location, "/sso/login") {
		return false
	}

	return true
}
