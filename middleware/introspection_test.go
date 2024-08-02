package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIntrospectAccessToken(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		var capturedToken string
		authorizationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedToken = r.FormValue("token")
			_, _ = w.Write([]byte(`{"active": true}`))
		}))
		response, err := IntrospectAccessToken("nekot", authorizationServer.URL, authorizationServer.Client())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !response.Active() {
			t.Fatalf("expected active token")
		}
		if capturedToken != "nekot" {
			t.Fatalf("unexpected token: %s", capturedToken)
		}
	})

}
