package main

import (
	"fmt"
	"github.com/SanteonNL/nuts-pep/middleware"
	"github.com/rs/zerolog/log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

const ListenAddressKey = "PEP_LISTEN_ADDRESS"
const TokenIntrospectionEndpoint = "PEP_TOKEN_INTROSPECTION_ENDPOINT"
const UpstreamURLKey = "PEP_UPSTREAM_URL"

func main() {
	config, err := parseConfig()
	if err != nil {
		panic(fmt.Sprintf("Configuration error: %v", err))
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL = config.UpstreamURL.JoinPath("/", r.In.URL.Path)
			r.Out.URL.RawQuery = r.In.URL.RawQuery
			r.Out.Host = config.UpstreamURL.Host
		},
		Transport: loggingRoundTripper{
			next:   http.DefaultTransport,
			logger: log.Logger,
		},
		ErrorHandler: func(writer http.ResponseWriter, request *http.Request, err error) {
			log.Warn().Err(err).Msgf("FHIR request failed (url=%s)", request.URL.String())
			http.Error(writer, "FHIR request failed: "+err.Error(), http.StatusBadGateway)
		},
	}
	log.Info().Msgf("Listening on %s, proxying to %s", config.ListenAddress, config.UpstreamURL.String())
	http.Handle("/", proxy)
	panic(http.ListenAndServe(config.ListenAddress, nil))
}

func parseConfig() (*Config, error) {
	tokenIntrospectionEndpoint := os.Getenv(TokenIntrospectionEndpoint)
	if tokenIntrospectionEndpoint == "" {
		return nil, fmt.Errorf("missing/invalid environment variable: %s", TokenIntrospectionEndpoint)
	}
	upstreamURLString := os.Getenv(UpstreamURLKey)
	upstreamURL, err := url.Parse(upstreamURLString)
	if err != nil {
		return nil, fmt.Errorf("missing/invalid environment variable: %s", UpstreamURLKey)
	}
	listenAddress := os.Getenv(ListenAddressKey)
	if listenAddress == "" {
		listenAddress = ":8080"
	}
	return &Config{
		Config: middleware.Config{
			TokenIntrospectionEndpoint: tokenIntrospectionEndpoint,
		},
		UpstreamURL:   upstreamURL,
		ListenAddress: listenAddress,
	}, nil
}

type Config struct {
	middleware.Config
	UpstreamURL   *url.URL
	ListenAddress string
}
