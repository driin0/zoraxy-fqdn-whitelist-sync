package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WhitelistEntry struct {
	EntryType int    `json:"EntryType"`
	CC        string `json:"CC"`
	IP        string `json:"IP"`
	Comment   string `json:"Comment"`
}

type AccessRuleInfo struct {
	ID               string `json:"ID"`
	Name             string `json:"Name"`
	WhitelistEnabled bool   `json:"WhitelistEnabled"`
}

type ZoraxyClient interface {
	ListWhitelistIP(ruleID string) ([]WhitelistEntry, error)
	AddWhitelistIP(ruleID, ip, comment string) error
	RemoveWhitelistIP(ruleID, ip string) error
}

type HTTPZoraxyClient struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

func NewHTTPZoraxyClient(zoraxyPort int, apiKey string) *HTTPZoraxyClient {
	return &HTTPZoraxyClient{
		BaseURL: fmt.Sprintf("http://127.0.0.1:%d", zoraxyPort),
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

type errorEnvelope struct {
	Error string `json:"error"`
}

// checkError reports an error when the body is a Zoraxy error envelope
// ({"error":"..."}). Success bodies ("OK" or a JSON array) unmarshal into
// errorEnvelope as a failure, leaving Error empty, so they return nil.
func checkError(body []byte) error {
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err == nil && env.Error != "" {
		return fmt.Errorf("zoraxy api error: %s", env.Error)
	}
	return nil
}

func (c *HTTPZoraxyClient) do(req *http.Request) ([]byte, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (c *HTTPZoraxyClient) ListWhitelistIP(ruleID string) ([]WhitelistEntry, error) {
	u := fmt.Sprintf("%s/plugin/api/whitelist/list?type=ip&id=%s", c.BaseURL, url.QueryEscape(ruleID))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if err := checkError(body); err != nil {
		return nil, err
	}
	var entries []WhitelistEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse whitelist list: %w", err)
	}
	return entries, nil
}

func (c *HTTPZoraxyClient) ListAccessRules() ([]AccessRuleInfo, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/plugin/api/access/list", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if err := checkError(body); err != nil {
		return nil, err
	}
	var rules []AccessRuleInfo
	if err := json.Unmarshal(body, &rules); err != nil {
		return nil, fmt.Errorf("parse access rules: %w", err)
	}
	return rules, nil
}

func (c *HTTPZoraxyClient) postForm(path string, form url.Values) error {
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body, err := c.do(req)
	if err != nil {
		return err
	}
	return checkError(body)
}

func (c *HTTPZoraxyClient) AddWhitelistIP(ruleID, ip, comment string) error {
	return c.postForm("/plugin/api/whitelist/ip/add", url.Values{
		"id":      {ruleID},
		"ip":      {ip},
		"comment": {comment},
	})
}

func (c *HTTPZoraxyClient) RemoveWhitelistIP(ruleID, ip string) error {
	return c.postForm("/plugin/api/whitelist/ip/remove", url.Values{
		"id": {ruleID},
		"ip": {ip},
	})
}
