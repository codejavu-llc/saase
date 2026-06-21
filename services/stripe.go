package services

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func generateRandomAlphabetStringStripe(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckStripe(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringStripe(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	data := url.Values{}
	data.Set("email", email)
	data.Set("password", "")
	data.Set("io_blackbox", "")
	data.Set("remember", "true")
	data.Set("merchant", "")
	data.Set("invite_code", "")
	data.Set("account_invite", "")
	data.Set("redirect", "/")
	data.Set("source", "main_login")
	data.Set("has_platform_authenticator", "false")
	data.Set("signing_algorithm", "SECP256R1")
	data.Set("public_key", "Amhx1zjMeLH1AkPnedZ5KdITVdx/zHsP3b0b+9flTL0j")
	data.Set("hcaptcha_response", "")
	data.Set("login_flow", "login")
	data.Set("placement_code", "")
	data.Set("px3", "")
	data.Set("pxvid", "8e8b8d2e-6cb2-11f1-9735-bed255ce89b9")
	data.Set("pxcts", "")

	req, err := http.NewRequest("POST", "https://dashboard.stripe.com/ajax/sessions/new", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Printf("Warning: Failed to create Stripe request: %v\n", err)
		return false
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: Stripe request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read Stripe response body: %v\n", err)
		return false
	}

	if strings.Contains(string(bodyBytes), "saml_required") {
		return true
	}

	return false
}
