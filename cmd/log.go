package main

import (
	"fmt"
	"github.com/rs/zerolog"
	"net/http"
	"strings"
)

type loggingRoundTripper struct {
	logger zerolog.Logger
	next   http.RoundTripper
}

func (l loggingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	l.logger.Info().Msgf("Proxying FHIR request: %s %s", request.Method, request.URL.String())
	if l.logger.Debug().Enabled() {
		var headers []string
		for key, values := range request.Header {
			headers = append(headers, fmt.Sprintf("(%s: %s)", key, strings.Join(values, ", ")))
		}
		l.logger.Debug().Msgf("Proxy request headers: %s", strings.Join(headers, ", "))
	}
	response, err := l.next.RoundTrip(request)
	if err != nil {
		l.logger.Warn().Err(err).Msgf("Proxied FHIR request failed (url=%s)", request.URL.String())
	} else {
		if l.logger.Debug().Enabled() {
			l.logger.Debug().Msgf("Proxied FHIR request response: %s", response.Status)
			var headers []string
			for key, values := range response.Header {
				headers = append(headers, fmt.Sprintf("(%s: %s)", key, strings.Join(values, ", ")))
			}
			l.logger.Debug().Msgf("Proxy response headers: %s", strings.Join(headers, ", "))
		}
	}
	return response, err
}
