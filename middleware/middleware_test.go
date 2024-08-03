package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMiddleware(t *testing.T) {
	authorizationServer := newTokenIntrospectionEndpoint(t, true)
	resourceEndpointCalled := false
	var userInfo map[string]interface{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", Secure(Config{
		TokenIntrospectionEndpoint: authorizationServer.URL,
		TokenIntrospectionClient:   authorizationServer.Client(),
	}, func(response http.ResponseWriter, request *http.Request) {
		resourceEndpointCalled = true
		userInfo = UserInfo(request.Context())
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("OK"))
	}))
	securedServer := httptest.NewServer(mux)
	t.Run("authorized", func(t *testing.T) {
		httpRequest, _ := http.NewRequest("GET", securedServer.URL, nil)
		httpRequest.Header.Add("Authorization", "Bearer yes")

		httpResponse, err := securedServer.Client().Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		if httpResponse.StatusCode != http.StatusOK {
			t.Fatal("expected HTTP status 200")
		}
		responseData, _ := io.ReadAll(httpResponse.Body)
		if string(responseData) != "OK" {
			t.Fatal("unexpected response")
		}
		if userInfo["sub"].(string) != "123" {
			t.Fatal("unexpected user information")
		}
	})
	t.Run("token not active", func(t *testing.T) {
		authorizationServer := newTokenIntrospectionEndpoint(t, false)
		mux := http.NewServeMux()
		resourceEndpointCalled := false
		mux.HandleFunc("/", Secure(Config{
			TokenIntrospectionEndpoint: authorizationServer.URL,
			TokenIntrospectionClient:   authorizationServer.Client(),
		}, func(response http.ResponseWriter, request *http.Request) {
			resourceEndpointCalled = true
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte("OK"))
		}))
		securedServer := httptest.NewServer(mux)

		httpRequest, _ := http.NewRequest("GET", securedServer.URL, nil)
		httpRequest.Header.Add("Authorization", "Bearer yes")

		httpResponse, err := securedServer.Client().Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		if httpResponse.StatusCode != http.StatusUnauthorized {
			t.Fatal("expected HTTP status 401")
		}
		if resourceEndpointCalled {
			t.Fatal("expected resource endpoint not to be called")
		}
	})
	t.Run("unauthorized response with protected-resource-metadata URL", func(t *testing.T) {
		mux := http.NewServeMux()
		baseURL, _ := url.Parse("https://example.com")
		mux.HandleFunc("/", Secure(Config{
			TokenIntrospectionEndpoint: authorizationServer.URL,
			TokenIntrospectionClient:   authorizationServer.Client(),
			BaseURL:                    baseURL,
		}, func(response http.ResponseWriter, request *http.Request) {
			response.WriteHeader(http.StatusOK)
		}))
		securedServer := httptest.NewServer(mux)

		httpRequest, _ := http.NewRequest("GET", securedServer.URL, nil)

		httpResponse, err := securedServer.Client().Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		if httpResponse.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected HTTP status 401, but was %d", httpResponse.StatusCode)
		}
		wwwAuthHeader := httpResponse.Header.Get("WWW-Authenticate")
		expectedResourceMetadata := `resource_metadata="` + baseURL.JoinPath(".well-known", baseURL.Path).String() + `"`
		if !strings.Contains(wwwAuthHeader, expectedResourceMetadata) {
			t.Fatalf("expected WWW-Authenticate header to contain: %s", expectedResourceMetadata)
		}
	})
	t.Run("no Authorization header", func(t *testing.T) {
		resourceEndpointCalled = false
		httpRequest, _ := http.NewRequest("GET", securedServer.URL, nil)

		httpResponse, err := securedServer.Client().Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		if httpResponse.StatusCode != http.StatusUnauthorized {
			t.Fatal("expected HTTP status 401")
		}
		wwwAuthHeader := httpResponse.Header.Get("WWW-Authenticate")
		if wwwAuthHeader != `Bearer error="invalid_request", error_description="missing Authorization header"` {
			t.Fatalf("unexpected WWW-Authenticate header: %s", wwwAuthHeader)
		}
		if resourceEndpointCalled {
			t.Fatal("expected resource endpoint not to be called")
		}
	})
	t.Run("invalid Authorization header", func(t *testing.T) {
		resourceEndpointCalled = false
		httpRequest, _ := http.NewRequest("GET", securedServer.URL, nil)
		httpRequest.Header.Add("Authorization", "Invalid")

		httpResponse, err := securedServer.Client().Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		if httpResponse.StatusCode != http.StatusUnauthorized {
			t.Fatal("expected HTTP status 401")
		}
		if resourceEndpointCalled {
			t.Fatal("expected resource endpoint not to be called")
		}
	})
	t.Run("invalid token type", func(t *testing.T) {
		resourceEndpointCalled = false
		httpRequest, _ := http.NewRequest("GET", securedServer.URL, nil)
		httpRequest.Header.Add("Authorization", "Invalid yes")

		httpResponse, err := securedServer.Client().Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		if httpResponse.StatusCode != http.StatusUnauthorized {
			t.Fatal("expected HTTP status 401")
		}
		if resourceEndpointCalled {
			t.Fatal("expected resource endpoint not to be called")
		}
	})
	t.Run("introspection error", func(t *testing.T) {
		resourceEndpointCalled = false
		authorizationServer.Close()
		httpRequest, _ := http.NewRequest("GET", securedServer.URL, nil)
		httpRequest.Header.Add("Authorization", "Bearer yes")

		httpResponse, err := securedServer.Client().Do(httpRequest)

		if err != nil {
			t.Fatal(err)
		}
		if httpResponse.StatusCode != http.StatusUnauthorized {
			t.Fatal("expected HTTP status 401")
		}
		if resourceEndpointCalled {
			t.Fatal("expected resource endpoint not to be called")
		}
	})
}

func TestIntrospectAccessToken(t *testing.T) {
	t.Run("non-OK status code", func(t *testing.T) {
		authorizationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		response, err := IntrospectAccessToken("token", authorizationServer.URL, authorizationServer.Client())
		if err.Error() != "http status: 500" {
			t.Fatalf("unexpected error: %v", err)
		}
		if response != nil {
			t.Fatal("expected nil response")
		}
	})
	t.Run("invalid JSON response", func(t *testing.T) {
		authorizationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("invalid"))
		}))
		response, err := IntrospectAccessToken("token", authorizationServer.URL, authorizationServer.Client())
		if err.Error() != "json decode error: invalid character 'i' looking for beginning of value" {
			t.Fatalf("unexpected error: %v", err)
		}
		if response != nil {
			t.Fatal("expected nil response")
		}
	})
}

func newTokenIntrospectionEndpoint(t *testing.T, active bool) *httptest.Server {
	authorizationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := make(map[string]interface{})
		response["active"] = active
		response["sub"] = "123"
		responseData, _ := json.Marshal(response)
		_, _ = w.Write(responseData)
	}))
	t.Cleanup(func() {
		authorizationServer.Close()
	})
	return authorizationServer
}
