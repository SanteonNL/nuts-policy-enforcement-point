package middleware

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"net/http"
	"strings"
)

// Secure wraps the given handler in middleware that checks the access token in the request headers.
// If the access token is valid, the handler is called. If the access token is invalid, a 401 Unauthorized response is returned.
func Secure(config Config, handler func(response http.ResponseWriter, request *http.Request)) func(response http.ResponseWriter, request *http.Request) {
	return func(response http.ResponseWriter, request *http.Request) {
		_, accessToken, err := parseAuthorizationHeader(request.Header.Get("Authorization"))
		if err != nil {
			respondUnauthorized(config, "invalid_request", err.Error(), response)
			return
		}
		introspectionResponse, err := IntrospectAccessToken(accessToken, config.TokenIntrospectionEndpoint, config.TokenIntrospectionClient)
		if err != nil {
			log.Error().Err(err).Msg("Failed to introspect access token")
			respondUnauthorized(config, "server_error", "couldn't verify access token", response)
			return
		}
		if !introspectionResponse.Active() {
			respondUnauthorized(config, "invalid_request", "invalid/expired token", response)
			return
		}
		handler(response, request)
	}
}

func respondUnauthorized(config Config, errorCode string, errorDescription string, response http.ResponseWriter) {
	// escape errorCode and errorDescription
	errorCode = strings.ReplaceAll(errorCode, `"`, `\"`)
	errorDescription = strings.ReplaceAll(errorDescription, `"`, `\"`)
	errorDescription = strings.ReplaceAll(errorDescription, `"`, `\"`)
	wwwAuthParams := []string{
		fmt.Sprintf(`error="%s"`, errorCode),
		fmt.Sprintf(`error_description="%s"`, errorDescription),
	}
	if config.BaseURL != nil {
		resourceMetadataURL := config.BaseURL.JoinPath(".well-known", config.BaseURL.Path)
		wwwAuthParams = append(wwwAuthParams, fmt.Sprintf(`resource_metadata="%s"`, resourceMetadataURL))
	}
	response.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer %s", strings.Join(wwwAuthParams, ", ")))
	response.WriteHeader(http.StatusUnauthorized)
}

func parseAuthorizationHeader(authorizationHeader string) (string, string, error) {
	if authorizationHeader == "" {
		return "", "", fmt.Errorf("missing Authorization header")
	}
	parts := strings.Split(authorizationHeader, " ")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid Authorization header")
	}
	if parts[0] != "Bearer" {
		return "", "", fmt.Errorf("unsupported token type")
	}
	return parts[0], parts[1], nil
}
