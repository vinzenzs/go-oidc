package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"

)

type AccessTokenVerifier struct {
	keySet KeySet
	config *Config
	issuer string
}

type AccessToken struct {
	Issuer            string
	Audience          []string
	Subject           string
	Expiry            time.Time
	IssuedAt          time.Time
	sigAlgorithm      string
	claims            []byte
	distributedClaims map[string]claimSource
}

type accessToken struct {
	Issuer       string                 `json:"iss"`
	Subject      string                 `json:"sub"`
	Audience     audience               `json:"aud"`
	Expiry       jsonTime               `json:"exp"`
	IssuedAt     jsonTime               `json:"iat"`
	NotBefore    *jsonTime              `json:"nbf"`
	Nonce        string                 `json:"nonce"`
	AtHash       string                 `json:"at_hash"`
	ClaimNames   map[string]string      `json:"_claim_names"`
	ClaimSources map[string]claimSource `json:"_claim_sources"`
}

func (v *AccessTokenVerifier) Verify(ctx context.Context, rawAccessToken string) (*AccessToken, error) {

	payload, err := parseJWT(rawAccessToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	}
	var token accessToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("oidc: failed to unmarshal claims: %v", err)
	}
	distributedClaims := make(map[string]claimSource)

	//step through the token to map claim names to claim sources"
	for cn, src := range token.ClaimNames {
		if src == "" {
			return nil, fmt.Errorf("oidc: failed to obtain source from claim name")
		}
		s, ok := token.ClaimSources[src]
		if !ok {
			return nil, fmt.Errorf("oidc: source does not exist")
		}
		distributedClaims[cn] = s
	}

	t := &AccessToken{
		Issuer:            token.Issuer,
		Subject:           token.Subject,
		Audience:          []string(token.Audience),
		Expiry:            time.Time(token.Expiry),
		IssuedAt:          time.Time(token.IssuedAt),
		claims:            payload,
		distributedClaims: distributedClaims,
	}

	// Check issuer.
	if !v.config.SkipIssuerCheck && t.Issuer != v.issuer {
		return nil, fmt.Errorf("oidc: id token issued by a different provider, expected %q got %q", v.issuer, t.Issuer)
	}

	// If a client ID has been provided, make sure it's part of the audience. SkipClientIDCheck must be true if ClientID is empty.
	//
	// This check DOES NOT ensure that the ClientID is the party to which the ID Token was issued (i.e. Authorized party).
	if !v.config.SkipClientIDCheck {
		if v.config.ClientID != "" {
			if !contains(t.Audience, v.config.ClientID) {
				return nil, fmt.Errorf("oidc: expected audience %q got %q", v.config.ClientID, t.Audience)
			}
		} else {
			return nil, fmt.Errorf("oidc: invalid configuration, clientID must be provided or SkipClientIDCheck must be set")
		}
	}

	// If a SkipExpiryCheck is false, make sure token is not expired.
	if !v.config.SkipExpiryCheck {
		now := time.Now
		if v.config.Now != nil {
			now = v.config.Now
		}
		nowTime := now()

		if t.Expiry.Before(nowTime) {
			return nil, &TokenExpiredError{Expiry: t.Expiry}
		}

		// If nbf claim is provided in token, ensure that it is indeed in the past.
		if token.NotBefore != nil {
			nbfTime := time.Time(*token.NotBefore)
			// Set to 5 minutes since this is what other OpenID Connect providers do to deal with clock skew.
			// https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/6.12.2/src/Microsoft.IdentityModel.Tokens/TokenValidationParameters.cs#L149-L153
			leeway := 5 * time.Minute

			if nowTime.Add(leeway).Before(nbfTime) {
				return nil, fmt.Errorf("oidc: current time %v before the nbf (not before) time: %v", nowTime, nbfTime)
			}
		}
	}

	if v.config.InsecureSkipSignatureCheck {
		return t, nil
	}

	var supportedSigAlgs []jose.SignatureAlgorithm
	for _, alg := range v.config.SupportedSigningAlgs {
		supportedSigAlgs = append(supportedSigAlgs, jose.SignatureAlgorithm(alg))
	}
	if len(supportedSigAlgs) == 0 {
		// If no algorithms were specified by both the config and discovery, default
		// to the one mandatory algorithm "RS256".
		supportedSigAlgs = []jose.SignatureAlgorithm{jose.RS256}
	}
	jws, err := jose.ParseSigned(rawAccessToken, supportedSigAlgs)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	}

	switch len(jws.Signatures) {
	case 0:
		return nil, fmt.Errorf("oidc: id token not signed")
	case 1:
	default:
		return nil, fmt.Errorf("oidc: multiple signatures on id token not supported")
	}
	sig := jws.Signatures[0]
	t.sigAlgorithm = sig.Header.Algorithm

	ctx = context.WithValue(ctx, parsedJWTKey, jws)
	gotPayload, err := v.keySet.VerifySignature(ctx, rawAccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature: %v", err)
	}

	// Ensure that the payload returned by the square actually matches the payload parsed earlier.
	if !bytes.Equal(gotPayload, payload) {
		return nil, errors.New("oidc: internal error, payload parsed did not match previous payload")
	}

	return t, nil
}