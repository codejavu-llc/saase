package services

import (
	"bytes"
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

type TeamViewerPayload struct {
	User        string `json:"user"`
	OAuthURL    string `json:"oAuthUrl"`
	URLFragment string `json:"urlFragment"`
}

func generateRandomAlphabetStringTeamViewer(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckTeamViewer(domain string, proxyURL string) bool {
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

	randomValue := generateRandomAlphabetStringTeamViewer(8)
	email := fmt.Sprintf("%s@%s", randomValue, domain)

	payload := TeamViewerPayload{
		User:        email,
		OAuthURL:    "",
		URLFragment: "",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Warning: Failed to marshal TeamViewer payload: %v\n", err)
		return false
	}

	req, err := http.NewRequest("POST", "https://login.teamviewer.com/LogOn/RedirectIfSsoActive", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Warning: Failed to create TeamViewer request: %v\n", err)
		return false
	}

	req.Header.Set("Cookie", "__xFlUD3rsEr4sd=f7d989ffb1314ed6874184f53ce3b424|9ZizJnCq8MJdKFtVuAiXnxs6khVfLFA9fbXGQispUwu-952BvPKwHA_vxFR5pldEc12jC3lQtMTkZ0zp-9R5Ij8Q1-o1")
	req.Header.Set("__xflud3rser4sd", "QYpBy94cbAG5yZMKtHpivqxZC1KL4CZ501brMYDuCvVBLzq41aWbfe3QEuyV6qCX_y2TVKR2OTkhw5MpYlewDPIABfI1")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: TeamViewer request failed to execute: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Warning: TeamViewer request returned unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Warning: Failed to read TeamViewer response body: %v\n", err)
		return false
	}

	bodyStr := string(bodyBytes)

	if strings.Contains(bodyStr, `"SsoToken"`) {
		return false
	}

	return true
}
