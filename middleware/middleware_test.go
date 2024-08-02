package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware(t *testing.T) {
	authorizationServer := newTokenIntrospectionEndpoint(t, true)
	mux := http.NewServeMux()
	mux.HandleFunc("/", Secure(Config{
		TokenIntrospectionEndpoint: authorizationServer.URL,
		TokenIntrospectionClient:   authorizationServer.Client(),
	}, func(response http.ResponseWriter, request *http.Request) {
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
	})
	t.Run("token not active", func(t *testing.T) {
		authorizationServer := newTokenIntrospectionEndpoint(t, false)
		mux := http.NewServeMux()
		mux.HandleFunc("/", Secure(Config{
			TokenIntrospectionEndpoint: authorizationServer.URL,
			TokenIntrospectionClient:   authorizationServer.Client(),
		}, func(response http.ResponseWriter, request *http.Request) {
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
	})
	t.Run("no Authorization header", func(t *testing.T) {
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
	})
	t.Run("invalid Authorization header", func(t *testing.T) {
		httpRequest, _ := http.NewRequest("GET", securedServer.URL, nil)
		httpRequest.Header.Add("Authorization", "Invalid")

		httpResponse, err := securedServer.Client().Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		if httpResponse.StatusCode != http.StatusUnauthorized {
			t.Fatal("expected HTTP status 401")
		}
	})
	t.Run("invalid token type", func(t *testing.T) {
		httpRequest, _ := http.NewRequest("GET", securedServer.URL, nil)
		httpRequest.Header.Add("Authorization", "Invalid yes")

		httpResponse, err := securedServer.Client().Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		if httpResponse.StatusCode != http.StatusUnauthorized {
			t.Fatal("expected HTTP status 401")
		}
	})
	t.Run("introspection error", func(t *testing.T) {
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
	})
}

func newTokenIntrospectionEndpoint(t *testing.T, active bool) *httptest.Server {
	authorizationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := make(map[string]interface{})
		response["active"] = active
		responseData, _ := json.Marshal(response)
		_, _ = w.Write(responseData)
	}))
	t.Cleanup(func() {
		authorizationServer.Close()
	})
	return authorizationServer
}
