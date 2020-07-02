package main

import (
	"errors"
	"net/http"

	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/dgrijalva/jwt-go"
)

// JWTAuthHandler provides the capability to authenticate incoming HTTP requests.
type JWTAuthHandler struct {
	Keys       map[string]string
	Next       http.Handler
	middleware *jwtmiddleware.JWTMiddleware
}

// NewJWTAuthHandler creates a new JWTAuthHandler, passing in a map of issuers to public RSA keys, and a
// time provider to allow for variation of the time.
func NewJWTAuthHandler(keys map[string]string, expectedScopes []string, next http.Handler) JWTAuthHandler {
	h := JWTAuthHandler{
		Keys: keys,
		Next: next,
	}
	h.middleware = jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Assume standard claims of "iss", "exp" and "iat".
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return nil, errors.New("JWT claims not found")
			}

			if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
				return nil, errors.New("token expired")
			}

			// Find the public key to match the issuer.
			issuerClaim, ok := claims["iss"]
			if !ok {
				return nil, errors.New("iss not found")
			}

			issuer, ok := issuerClaim.(string)
			if !ok {
				return nil, errors.New("iss was not in correct format")
			}

			pub, ok := keys[issuer]
			if !ok {
				return nil, errors.New("iss not valid")
			}

			// Check scope (if specified)
			if len(expectedScopes) > 0 {
				scopeClaim, ok := claims["scope"]
				if !ok {
					return nil, errors.New("missing scope")
				}
				scopes, ok := parseScopes(scopeClaim)
				if !ok {
					return nil, errors.New("scope was not in correct format")
				}
				ok = verifyScopes(expectedScopes, scopes)
				if !ok {
					return nil, errors.New("invalid scope")
				}
			}

			return jwt.ParseRSAPublicKeyFromPEM([]byte(pub))
		},
		// When set, the middleware verifies that tokens are signed with the specific signing algorithm
		// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
		// Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
		SigningMethod: jwt.SigningMethodRS256,
	})
	return h
}

func parseScopes(claim interface{}) ([]string, bool) {
	iscopes, ok := claim.([]interface{})
	if !ok {
		return nil, false
	}

	scopes := make([]string, len(iscopes))
	for i, s := range iscopes {
		scopes[i], ok = s.(string)
		if !ok {
			return nil, false
		}
	}
	return scopes, true
}

func verifyScopes(expected []string, actual []string) bool {
	valid := true
	for _, e := range expected {
		valid = valid && verifyScope(e, actual)
	}
	return valid
}

func verifyScope(expected string, actual []string) bool {
	valid := false
	for _, as := range actual {
		if as == expected {
			valid = true
			break
		}
	}
	return valid
}

func (jwth JWTAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	jwth.middleware.Handler(jwth.Next).ServeHTTP(w, r)
}
