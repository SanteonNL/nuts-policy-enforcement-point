package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type IntrospectionResult map[string]interface{}

func (i IntrospectionResult) Active() bool {
	b, ok := i["active"].(bool)
	return ok && b
}

func IntrospectAccessToken(accessToken string, endpoint string, httpClient *http.Client) (*IntrospectionResult, error) {
	body := url.Values{
		"token": {accessToken},
	}
	httpResponse, err := httpClient.PostForm(endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("http error: %w", err)
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return nil, fmt.Errorf("http status: %d", httpResponse.StatusCode)
	}
	var result IntrospectionResult
	if err := json.NewDecoder(httpResponse.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("json decode error: %w", err)
	}
	return &result, nil
}
