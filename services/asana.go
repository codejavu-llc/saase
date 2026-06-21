package services

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func generateRandomAlphabetStringAsana(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckAsana(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringAsana(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("e", email)
	_ = writer.WriteField("u", "https://app.asana.com/?rr=693458")
	_ = writer.WriteField("src", "login")
	_ = writer.WriteField("email_hint", "")
	_ = writer.WriteField("recent_saml_email", "null")
	_ = writer.WriteField("wa", "undefined")
	_ = writer.WriteField("is_web_only", "undefined")
	_ = writer.WriteField("otk", "undefined")
	_ = writer.WriteField("share_link_key", "")
	_ = writer.WriteField("share_link_domain", "")
	_ = writer.WriteField("utm_campaign", "")
	_ = writer.WriteField("utm_medium", "")
	_ = writer.WriteField("utm_source", "")
	_ = writer.WriteField("xsrf_token", "test123")
	_ = writer.Close()

	req, err := http.NewRequest("POST", "https://app.asana.com/-/web_login_options", body)
	if err != nil {
		fmt.Printf("Warning: Failed to create Asana request: %v\n", err)
		return false
	}

	req.Header.Set("Cookie", "xsrf_token=test123")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Asana request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: Asana request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Asana response body: %v\n", err)
		return false
	}

	if strings.Contains(string(bodyBytes), "saml_sso") {
		return true
	}

	return false
}
