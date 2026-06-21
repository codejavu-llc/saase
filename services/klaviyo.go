package services

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func CheckKlaviyo(domain string, proxyURL string) bool {
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

	organizationName := domain
	if dotIdx := strings.Index(domain, "."); dotIdx != -1 {
		organizationName = domain[:dotIdx]
	}

	csrfToken := "oJ0oDDw0aB8rj5SgoT6iSA92tXeqcx9s"

	var bodyBytes []byte
	var contentType string

	buildMultipartBody := func() ([]byte, string, error) {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)

		if err := writer.WriteField("workplace_id", organizationName); err != nil {
			return nil, "", err
		}
		if err := writer.WriteField("remember_me", "false"); err != nil {
			return nil, "", err
		}
		if err := writer.WriteField("next", ""); err != nil {
			return nil, "", err
		}
		if err := writer.Close(); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), writer.FormDataContentType(), nil
	}

	var err error
	bodyBytes, contentType, err = buildMultipartBody()
	if err != nil {
		fmt.Printf("Warning: Failed to create Klaviyo multipart body: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://www.klaviyo.com/sso/login", bytes.NewReader(bodyBytes))
	if err != nil {
		fmt.Printf("Warning: Failed to create Klaviyo request: %v\n", err)
		return false
	}

	req.Header.Set("Cookie", fmt.Sprintf("kl_csrftoken=%s", csrfToken))
	req.Header.Set("X-Csrftoken", csrfToken)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	req.Header.Set("Origin", "https://www.klaviyo.com")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Klaviyo request failed to execute: %v\n", err)
		return false
	}

	if resp.StatusCode == 403 {
		resp.Body.Close()
		
		var newToken string
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "kl_csrftoken" {
				newToken = cookie.Value
				break
			}
		}

		if newToken != "" {
			req2, err := http.NewRequest("POST", "https://www.klaviyo.com/sso/login", bytes.NewReader(bodyBytes))
			if err != nil {
				return false
			}

			req2.Header.Set("Cookie", fmt.Sprintf("kl_csrftoken=%s", newToken))
			req2.Header.Set("X-Csrftoken", newToken)
			req2.Header.Set("Content-Type", contentType)
			req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
			req2.Header.Set("Origin", "https://www.klaviyo.com")

			resp, err = client.Do(req2)
			if err != nil {
				return false
			}
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Klaviyo response body: %v\n", err)
		return false
	}

	if strings.Contains(string(respBody), "Workplace ID does not exist.") {
		return false
	}

	return true
}
