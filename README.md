# Nuts Policy Enforcement Point (PEP)

This library provides a Golang HTTP middleware function that can be used to enforce Nuts authn/authz policies on incoming HTTP requests.
It provides the following features:

- Authenticate incoming requests to an upstream Resource Server (e.g. FHIR API) using the OAuth2 Token Introspection (https://www.rfc-editor.org/rfc/rfc7662.html) endpoint of the Nuts Authorization Server.
- In (near) future: authorize incoming requests given the configured policy.
- In (near) future: support verifying DPoP (Demonstrating Proof-of-Possession, https://www.rfc-editor.org/rfc/rfc9449.html) access tokens.
- Support for informing the OAuth2 client of the Nuts Authorization Server through https://www.ietf.org/archive/id/draft-ietf-oauth-resource-metadata-07.html

It can also be used as standalone, reverse proxy deployed in front of the upstream Resource Server.
