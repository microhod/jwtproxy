package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func TestJWTHandling(t *testing.T) {

	validIssuer := "example.com"
	requiredScope := []string{"required-scope"}

	tests := []struct {
		name               string
		request            func(string) *http.Request
		iss                interface{}
		exp                interface{}
		scope              interface{}
		validateScope      bool
		expectedStatusCode int
		expectedBody       string
		expectedNextCalled bool
	}{
		// Valid token Tests
		{
			name:               "Valid exp, valid issuer, valid scope",
			iss:                validIssuer,
			exp:                getExpiry(true),
			scope:              requiredScope,
			validateScope:      true,
			expectedStatusCode: http.StatusOK,
			expectedBody:       "OK",
			expectedNextCalled: true,
		},
		{
			name:               "Valid exp, valid issuer, no scope",
			iss:                validIssuer,
			exp:                getExpiry(true),
			expectedStatusCode: http.StatusOK,
			expectedBody:       "OK",
			expectedNextCalled: true,
		},
		// Token/Header format Tests
		{
			name: "Missing JWT header",
			request: func(token string) *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				return r
			},
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Required authorization token not found",
		},
		{
			name: "Junk format for authorization header",
			request: func(token string) *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Add("Authorization", "nonsense")
				return r
			},
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Authorization header format must be Bearer {token}",
		},
		{
			name: "Invalid JWT",
			request: func(token string) *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Add("Authorization", "Bearer sfdjkfjk.sdsdads.asdasd")
				return r
			},
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "invalid character",
		},
		// exp Tests
		{
			name:               "Missing exp field",
			iss:                validIssuer,
			scope:              requiredScope,
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "token expired",
		},
		{
			name:               "Expired token",
			iss:                validIssuer,
			exp:                getExpiry(false),
			scope:              requiredScope,
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "token expired",
		},
		// iss Tests
		{
			name:               "Issuer happens to be a number",
			iss:                12345,
			exp:                getExpiry(true),
			scope:              requiredScope,
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "iss was not in correct format",
		},
		{
			name:               "Unknown issuer",
			iss:                "unknown.com",
			exp:                getExpiry(true),
			scope:              requiredScope,
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "iss not valid",
		},
		// scope Tests
		{
			name:               "Missing scope",
			iss:                validIssuer,
			exp:                getExpiry(true),
			validateScope:      true,
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "missing scope",
		},
		{
			name:               "Scope is a number",
			iss:                validIssuer,
			exp:                getExpiry(true),
			scope:              1234,
			validateScope:      true,
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "scope was not in correct format",
		},
		{
			name:               "Scope is a list of numbers",
			iss:                validIssuer,
			exp:                getExpiry(true),
			scope:              []int64{12, 34},
			validateScope:      true,
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "scope was not in correct format",
		},
		{
			name:               "Invalid scope",
			iss:                validIssuer,
			exp:                getExpiry(true),
			scope:              []string{"no required scope"},
			validateScope:      true,
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "invalid scope",
		},
	}

	for _, test := range tests {

		token, publicKey, err := getTestToken(test.iss, test.exp, test.scope)
		if err != nil {
			t.Errorf("Failed to create token with error: %v", err)
		}

		if test.request == nil {
			test.request = func(token string) *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Add("Authorization", fmt.Sprint("Bearer ", token))
				return r
			}
		}

		keys := map[string]string{validIssuer: publicKey}

		actualNextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
			actualNextCalled = true
		})

		var scope []string
		if !test.validateScope {
			scope = []string{}
		} else {
			scope = requiredScope
		}

		handler := NewJWTAuthHandler(keys, scope, next)
		recorder := httptest.NewRecorder()

		// Act
		handler.ServeHTTP(recorder, test.request(token))

		// Assert
		actual := recorder.Result()

		if test.expectedNextCalled != actualNextCalled {
			t.Errorf("%s: expected next called %v, but got %v", test.name, test.expectedNextCalled, actualNextCalled)
		}

		if actual.StatusCode != test.expectedStatusCode {
			t.Errorf("%s: expected status code %v, but got %v", test.name, test.expectedStatusCode, actual.StatusCode)
		}

		actualBody, err := ioutil.ReadAll(actual.Body)
		if err != nil {
			t.Errorf("%s: failed to read body with error: %v", test.name, err)

		}
		if !strings.HasPrefix(string(actualBody), test.expectedBody) {
			t.Errorf("%s: expected body to start with '%v' but got '%v'", test.name, test.expectedBody, string(actualBody))
		}
	}
}

func getTestToken(iss interface{}, exp interface{}, scope interface{}) (string, string, error) {
	claimMap := map[string]interface{}{}

	if iss != nil {
		claimMap["iss"] = iss
	}
	if exp != nil {
		claimMap["exp"] = exp
	}
	if scope != nil {
		claimMap["scope"] = scope
	}

	claims := jwt.MapClaims(claimMap)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		return "", "", err
	}
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", "", err
	}
	publicKey, err := EncodePublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	return tokenString, string(publicKey), nil
}

func getExpiry(valid bool) int64 {
	var exp int64
	if valid {
		exp = time.Now().Add(time.Hour).Unix()
	} else {
		exp = time.Now().Add(time.Duration(-1) * time.Hour).Unix()
	}
	return exp
}
