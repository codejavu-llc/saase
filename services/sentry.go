package services

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func CheckSentry(domain string, proxyURL string) bool {
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

	req1, err := http.NewRequest("GET", "https://sentry.io/auth/login/", nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Sentry request 1: %v\n", err)
		return false
	}
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Printf("Warning: Sentry request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp1.Body.Close()

	var sentrySc, session string
	for _, cookie := range resp1.Cookies() {
		if cookie.Name == "sentry-sc" {
			sentrySc = cookie.Value
		} else if cookie.Name == "session" {
			session = cookie.Value
		}
	}

	bodyBytes1, err := io.ReadAll(resp1.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Sentry response 1 body: %v\n", err)
		return false
	}

	re := regexp.MustCompile(`name="csrfmiddlewaretoken"\s+value="([^"]+)"`)
	matches := re.FindStringSubmatch(string(bodyBytes1))
	if len(matches) < 2 || sentrySc == "" || session == "" {
		return false
	}
	csrfToken := matches[1]

	organizationName := domain
	if dotIdx := strings.Index(domain, "."); dotIdx != -1 {
		organizationName = domain[:dotIdx]
	}

	data2 := url.Values{}
	data2.Set("csrfmiddlewaretoken", csrfToken)
	data2.Set("op", "sso")
	data2.Set("organization", organizationName)

	req2, err := http.NewRequest("POST", "https://sentry.io/auth/login/", strings.NewReader(data2.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create Sentry request 2: %v\n", err)
		return false
	}

	req2.Header.Set("Cookie", fmt.Sprintf("sentry-sc=%s; session=%s", sentrySc, session))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: Sentry request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	location := resp2.Header.Get("Location")
	
	targetPath := fmt.Sprintf("/auth/login/%s/", organizationName)
	if strings.Contains(location, targetPath) {
		return true
	}

	return false
}
