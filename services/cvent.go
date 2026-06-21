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

func CheckCvent(domain string, proxyURL string) bool {
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

	req1, err := http.NewRequest("GET", "https://app.cvent.com/subscribers/Login.aspx", nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Cvent request 1: %v\n", err)
		return false
	}
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Printf("Warning: Cvent request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp1.Body.Close()

	bodyBytes1, err := io.ReadAll(resp1.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Cvent response 1 body: %v\n", err)
		return false
	}

	bodyStr := string(bodyBytes1)

	reEvent := regexp.MustCompile(`id="__EVENTVALIDATION"\s+value="([^"]+)"`)
	reView := regexp.MustCompile(`id="__VIEWSTATE"\s+value="([^"]+)"`)

	matchEvent := reEvent.FindStringSubmatch(bodyStr)
	matchView := reView.FindStringSubmatch(bodyStr)

	if len(matchEvent) < 2 || len(matchView) < 2 {
		return false
	}

	eventValidation := matchEvent[1]
	viewState := matchView[1]

	organizationName := domain
	if dotIdx := strings.Index(domain, "."); dotIdx != -1 {
		organizationName = domain[:dotIdx]
	}

	data2 := url.Values{}
	data2.Set("__EVENTTARGET", "")
	data2.Set("__EVENTARGUMENT", "")
	data2.Set("__VIEWSTATE", viewState)
	data2.Set("__VIEWSTATEGENERATOR", "")
	data2.Set("__VIEWSTATEENCRYPTED", "")
	data2.Set("__EVENTVALIDATION", eventValidation)
	data2.Set("account", "")
	data2.Set("username", "")
	data2.Set("password", "")
	data2.Set("organizationId", organizationName)
	data2.Set("btnLoginSso", "Log In")

	req2, err := http.NewRequest("POST", "https://app.cvent.com/subscribers/Login.aspx?ReturnUrl=%2fsubscribers%2f", strings.NewReader(data2.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create Cvent request 2: %v\n", err)
		return false
	}

	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: Cvent request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == 302 {
		return true
	}

	return false
}
