package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/arrikto/oidc-authservice/common"
	"golang.org/x/oauth2"
)

// RevocationEndpoint parses the OIDC Provider claims from the discovery document
// and tries to find the revocation_endpoint.
func RevocationEndpoint(p Provider) (string, error) {
	claims := struct {
		RevocationEndpoint string `json:"revocation_endpoint"`
	}{}
	if err := p.Claims(&claims); err != nil {
		return "", fmt.Errorf("Error unmarshalling provider doc into struct: %w", err)
	}
	if claims.RevocationEndpoint == "" {
		return "", errors.New("Provider doesn't have a revocation_endpoint")
	}
	return claims.RevocationEndpoint, nil
}

// RevokeTokens is a helper that takes an oauth2.Token and revokes the access and refresh tokens.
// If no tokens are found, it succeeds.
func RevokeTokens(ctx context.Context, revocationEndpoint string, token *oauth2.Token, clientID, clientSecret string) error {
	log := common.StandardLogger()

	if token.RefreshToken != "" {
		log.Info("Attempting to revoke refresh token...")
		err := revokeToken(ctx, revocationEndpoint, token.RefreshToken, "refresh_token", clientID, clientSecret)
		if err != nil {
			return fmt.Errorf("Failed to revoke refresh token: %w", err)
		}
		log.Info("Successfully revoked refresh token")
	}
	if token.AccessToken != "" {
		log.Info("Attempting to revoke access token...")
		err := revokeToken(ctx, revocationEndpoint, token.AccessToken, "access_token", clientID, clientSecret)
		if err != nil {
			code := err.(*common.RequestError).Response.StatusCode
			if code == 400 {
				bodyMap := make(map[string]string)

				err2 := json.Unmarshal(err.(*common.RequestError).Body, &bodyMap)
				if err2 != nil {
					err2 = fmt.Errorf("Error while attempting to unmarshal the body of the request: %w", err2)
					full_error := errors.Join(err, err2)
					return fmt.Errorf("Error while attempting to revoke access token: %w", full_error)
				}

				if bodyMap["error"] == "unsupported_token_type" {
					log.Warning("The Identity Provider does not support revoking access tokens")
					return nil
				}
			}
			return fmt.Errorf("Failed to revoke access token: %w", err)
		} else {
			log.Info("Successfully revoked access token")
		}
	}
	return nil
}

// revokeToken takes care of revoking an access/refresh token to the IdP.
// The revocation procedure is described in RFC7009:
// https://tools.ietf.org/html/rfc7009
func revokeToken(ctx context.Context, revocationEndpoint string, token, tokenType, clientID, clientSecret string) error {
	// Verify revocation_endpoint has https url
	if !strings.HasPrefix(revocationEndpoint, "https") {
		return fmt.Errorf("Revocation endpoint (%v) MUST use https", revocationEndpoint)
	}
	values := url.Values{}
	values.Set("token", token)
	values.Set("token_type_hint", tokenType)
	req, err := http.NewRequest(http.MethodPost, revocationEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// We only support basic auth now, we may need to support other methods in the future
	// See: https://github.com/golang/oauth2/blob/bf48bf16ab8d622ce64ec6ce98d2c98f916b6303/internal/token.go#L204-L215
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := common.DoRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("Error contacting revocation endpoint: %w", err)
	}
	if code := resp.StatusCode; code != 200 {
		// Read body to include in error for debugging purposes.
		// According to RFC6749 (https://tools.ietf.org/html/rfc6749#section-5.2)
		// the body should be in JSON, if we want to parse it in the future.
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return &common.RequestError{
				Response: resp,
				Body:     body,
				Err:      fmt.Errorf("Revocation endpoint returned code %v, failed to read body: %v", code, err),
			}
		}
		return &common.RequestError{
			Response: resp,
			Body:     body,
			Err:      fmt.Errorf("Revocation endpoint returned code %v, server returned: %v", code, body),
		}
	}
	return nil
}
