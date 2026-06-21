package services

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func CheckDixa(domain string, proxyURL string) bool {
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

	req1URL := "https://auth0.login.dixa.com/authorize?client_id=greMPi7FKxBlEYEXROSD7Vv9drMjiJ0u&scope=openid+profile+email&redirect_uri=https%3A%2F%2Faccounts.dixa.com%2Fsignin%2Fsso-callback%3Fdesktop%3Dfalse&response_type=code&response_mode=query"
	req1, err := http.NewRequest("GET", req1URL, nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create Dixa request 1: %v\n", err)
		return false
	}
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Printf("Warning: Dixa request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp1.Body.Close()

	var auth0Cookie string
	for _, cookie := range resp1.Cookies() {
		if cookie.Name == "auth0" {
			auth0Cookie = cookie.Value
			break
		}
	}

	loc1 := resp1.Header.Get("Location")
	if loc1 == "" {
		return false
	}

	parsedLoc1, err := url.Parse(loc1)
	if err != nil {
		return false
	}

	stateValue := parsedLoc1.Query().Get("state")
	if stateValue == "" || auth0Cookie == "" {
		return false
	}

	organizationName := domain
	if dotIdx := strings.Index(domain, "."); dotIdx != -1 {
		organizationName = domain[:dotIdx]
	}

	data2 := url.Values{}
	data2.Set("state", stateValue)
	data2.Set("organizationName", organizationName)

	req2URL := fmt.Sprintf("https://auth0.login.dixa.com/u/organization?state=%s", url.QueryEscape(stateValue))
	req2, err := http.NewRequest("POST", req2URL, strings.NewReader(data2.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create Dixa request 2: %v\n", err)
		return false
	}

	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Cookie", fmt.Sprintf("auth0=%s", auth0Cookie))
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: Dixa request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	loc2 := resp2.Header.Get("Location")
	if strings.Contains(loc2, "/authorize/resume") {
		return true
	}

	return false
}
