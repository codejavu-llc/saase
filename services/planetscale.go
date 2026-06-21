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

func CheckPlanetScale(domain string, proxyURL string) bool {
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

	req1, err := http.NewRequest("GET", "https://auth.planetscale.com/sso", nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create PlanetScale request 1: %v\n", err)
		return false
	}
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp1, err := client.Do(req1)
	if err != nil {
		fmt.Printf("Warning: PlanetScale request 1 failed to execute: %v\n", err)
		return false
	}
	defer resp1.Body.Close()

	var apiBbSession string
	for _, cookie := range resp1.Cookies() {
		if cookie.Name == "_api_bb_session" {
			apiBbSession = cookie.Value
			break
		}
	}

	bodyBytes1, err := io.ReadAll(resp1.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read PlanetScale response 1 body: %v\n", err)
		return false
	}

	re := regexp.MustCompile(`name="csrf-token"\s+content="([^"]+)"|<meta\s+content="([^"]+)"\s+name="csrf-token"|<meta\s+name="csrf-token"\s+content="([^"]+)"`)
	matches := re.FindStringSubmatch(string(bodyBytes1))
	
	var csrfToken string
	if len(matches) > 0 {
		for i := 1; i < len(matches); i++ {
			if matches[i] != "" {
				csrfToken = matches[i]
				break
			}
		}
	}

	if csrfToken == "" || apiBbSession == "" {
		return false
	}

	organizationName := domain
	if dotIdx := strings.Index(domain, "."); dotIdx != -1 {
		organizationName = domain[:dotIdx]
	}

	data2 := url.Values{}
	data2.Set("authenticity_token", csrfToken)
	data2.Set("org", organizationName)

	req2, err := http.NewRequest("POST", "https://auth.planetscale.com/sso", strings.NewReader(data2.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create PlanetScale request 2: %v\n", err)
		return false
	}

	req2.Header.Set("Cookie", fmt.Sprintf("_api_bb_session=%s", apiBbSession))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Printf("Warning: PlanetScale request 2 failed to execute: %v\n", err)
		return false
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == 302 {
		return true
	}

	return false
}
