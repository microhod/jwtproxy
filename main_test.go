package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestGetApp(t *testing.T) {
	tests := []struct {
		remoteURL 			 string
		remoteHostHeader string
		keys  					 string
		port 				 		 string
		health  				 string
		prefix 			 		 string
		scopes 			 		 string
	}{
		{
			remoteURL:				"example.com",
			remoteHostHeader: "",
			keys:							"keys.json",
			port:							"1234",
			health:						"/health",
			prefix:						"",
			scopes:						"test-scope-1,test-scope-2",
		},
	}

	for _, test := range tests {
		flag.Set("remoteURL", test.remoteURL)
		flag.Set("remoteHostHeader", test.remoteHostHeader)
		flag.Set("keys", test.keys)
		flag.Set("port", test.port)
		flag.Set("health", test.health)
		flag.Set("prefix", test.prefix)
		flag.Set("scopes", test.scopes)

		port, _, err := getApp()
		if err != nil {
			t.Errorf("Failed to configure App, got error: %s", err.Error())
		}
		if port != test.port {
			t.Errorf("Expected port %s but got %s", test.port, port)
		}
	}
}

func TestThatPathsAreJoinedWithASlash(t *testing.T) {
	tests := []struct {
		a        string
		b        string
		expected string
	}{
		{
			a:        "/test/",
			b:        "/b/",
			expected: "/test/b/",
		},
		{
			a:        "test",
			b:        "b",
			expected: "test/b",
		},
		{
			a:        "test",
			b:        "/b",
			expected: "test/b",
		},
		{
			a:        "test/",
			b:        "b",
			expected: "test/b",
		},
	}

	for _, test := range tests {
		actual := singleJoiningSlash(test.a, test.b)
		if actual != test.expected {
			t.Errorf("for '%v' and '%v', expected '%v' got '%v'", test.a, test.b, test.expected, actual)
		}
	}
}

func TestGetPort(t *testing.T) {
	tests := []struct {
		name         string
		flagValue		 string
		envValue     string
		pass         bool
		errorMessage string
	}{
		{
			name:     "Env Var valid",
			envValue: "1234",
			pass:     true,
		},
		{
			name:         "Env Var not set",
			pass:         false,
			errorMessage: "JWTPROXY_LISTEN_PORT environment variable or port command line flag not found",
		},
	}

	for _, test := range tests {
		// setup
		flag.Set("port", test.flagValue)
		os.Setenv("JWTPROXY_LISTEN_PORT", test.envValue)
		// act
		actual, err := getPort()
		// assert

		if test.pass {
			if err != nil {
				t.Errorf("%s: Expected no err, got error: %s", test.name, err.Error())
			}
			if actual != test.envValue {
				t.Errorf("%s: Expected value '%s' but got %s", test.name, test.envValue, actual)
			}
		} else {
			if err == nil {
				t.Errorf("%s: Expected err, got nil", test.name)
			}
			if !strings.Contains(err.Error(), test.errorMessage) {
				t.Errorf("%s: Expected error message '%s' but got '%s'", test.name, test.errorMessage, err.Error())
			}
		}
	}
}

func TestGetRemoteURL(t *testing.T) {
	tests := []struct {
		name         string
		envValue     string
		flagValue 	 string
		pass         bool
		errorMessage string
	}{
		{
			name:     "Env Var valid",
			envValue: "https://example.com",
			pass:     true,
		},
		{
			name:         "Env Var not set",
			pass:         false,
			errorMessage: "JWTPROXY_REMOTE_URL environment variable or remoteURL command line flag not found",
		},
		{
			name:         "Env Var invalid",
			envValue:     string(0x7f),
			pass:         false,
			errorMessage: "failed to parse remoteURL",
		},
	}

	for _, test := range tests {
		// setup
		flag.Set("remoteURL", test.flagValue)
		os.Setenv("JWTPROXY_REMOTE_URL", test.envValue)
		// act
		actual, err := getRemoteURL()
		// assert

		if test.pass {
			if err != nil {
				t.Errorf("%s: Expected no err, got error: %s", test.name, err.Error())
			}
			if actual.String() != test.envValue {
				t.Errorf("%s: Expected value '%v' but got %v", test.name, test.envValue, actual)
			}
		} else {
			if err == nil {
				t.Errorf("%s: Expected err, got nil", test.name)
			}
			if !strings.Contains(err.Error(), test.errorMessage) {
				t.Errorf("%s: Expected error message '%s' but got '%s'", test.name, test.errorMessage, err.Error())
			}
		}
	}
}

func TestGetKeysFromConfigFile(t *testing.T) {
	tests := []struct {
		name         string
		flagValue		 string
		envValue     string
		pass         bool
		errorMessage string
	}{
		{
			name:     "Valid file",
			envValue: "keys.json",
			pass:     true,
		},
		{
			name:         "Missing file",
			envValue:     "file_does_not_exist.json",
			pass:         false,
			errorMessage: "Failed to open file",
		},
	}

	for _, test := range tests {
		// setup
		flag.Set("keys", test.flagValue)
		os.Setenv("JWTPROXY_CONFIG", test.envValue)
		// act
		actual, err := getKeysFromConfigFile()
		// assert

		if test.pass {
			if err != nil {
				t.Errorf("%s: Expected no err, got error: %s", test.name, err.Error())
			}

			file, _ := ioutil.ReadFile(test.envValue)
			var expected map[string]string
			_ = json.Unmarshal([]byte(file), &expected)

			if !mapsAreEqual(actual, expected) {
				t.Errorf("%s: Expected value '%v' but got %v", test.name, test.envValue, actual)
			}
		} else {
			if err == nil {
				t.Errorf("%s: Expected err, got nil", test.name)
			}
			if !strings.Contains(err.Error(), test.errorMessage) {
				t.Errorf("%s: Expected error message '%s' but got '%s'", test.name, test.errorMessage, err.Error())
			}
		}
	}
}

func TestGetKeysFromEnvironment(t *testing.T) {
	tests := []struct {
		input         []string
		expected      map[string]string
		expectedError string
	}{
		{
			input: []string{"JWTPROXY_ISSUER_0=example.com", "JWTPROXY_PUBLIC_KEY_0=dsfdsfdsfdsf"},
			expected: map[string]string{
				"example.com": "dsfdsfdsfdsf",
			},
		},
		{
			input:    []string{"unrelated=something"},
			expected: map[string]string{},
		},
		{
			input:         []string{"JWTPROXY_ISSUER_1=example.com", "JWTPROXY_PUBLIC_KEY_0=dsfdsfdsfdsf"},
			expected:      map[string]string{},
			expectedError: "could not find a matching JWTPROXY_PUBLIC_KEY_1 value for JWTPROXY_ISSUER_1",
		},
	}

	for _, test := range tests {
		actual, err := getKeysFromEnvironment(test.input)
		if err != nil && test.expectedError == "" {
			t.Error(err)
		}
		if test.expectedError != "" && err == nil {
			t.Errorf("for input '%v', expected error '%v', got nil", test.input, test.expectedError)
		}
		if !mapsAreEqual(actual, test.expected) {
			t.Errorf("for input '%v', expected '%v', got '%v'", test.input, test.expected, actual)
		}
	}
}

func TestGetHealthCheckURI(t *testing.T) {
	tests := []struct {
		name         string
		flagValue		 string
		envValue     string
	}{
		{
			name:     "Env Var valid",
			envValue: "https://example.com/health",
		},
	}

	for _, test := range tests {
		// setup
		flag.Set("health", test.flagValue)
		os.Setenv("JWTPROXY_HEALTHCHECK_URI", test.envValue)
		// act
		actual := getHealthCheckURI()
		// assert
		if actual != test.envValue {
			t.Errorf("%s: Expected value '%v' but got %v", test.name, test.envValue, actual)
		}
	}
}

func TestGetPrefix(t *testing.T) {
	tests := []struct {
		name         string
		flagValue		 string
		envValue     string
	}{
		{
			name:     "Env Var valid",
			envValue: "testing-prefix",
		},
	}

	for _, test := range tests {
		// setup
		flag.Set("prefix", test.flagValue)
		os.Setenv("JWTPROXY_PREFIX", test.envValue)
		// act
		actual := getPrefix()
		// assert
		if actual != test.envValue {
			t.Errorf("%s: Expected value '%v' but got %v", test.name, test.envValue, actual)
		}
	}
}

func TestGetRemoteHostHeader(t *testing.T) {
	tests := []struct {
		name         string
		flagValue		 string
		envValue     string
	}{
		{
			name:     "Env Var valid",
			envValue: "testing-header",
		},
	}

	for _, test := range tests {
		// setup
		flag.Set("remoteHostHeader", test.flagValue)
		os.Setenv("JWTPROXY_REMOTE_HOST_HEADER", test.envValue)
		// act
		actual := getRemoteHostHeader()
		// assert
		if actual != test.envValue {
			t.Errorf("%s: Expected value '%v' but got %v", test.name, test.envValue, actual)
		}
	}
}

func TestGetScopes(t *testing.T) {
	tests := []struct {
		name      string
		flagValue string
		envValue  string
		expected  []string
	}{
		{
			name:     "Scope Env Var not set",
			expected: []string{},
		},
		{
			name:     "Scope Env Var set",
			envValue: "testscope1,testscope2",
			expected: []string{"testscope1", "testscope2"},
		},
	}

	for _, test := range tests {
		// setup
		flag.Set("scopes", test.flagValue)
		os.Setenv("JWTPROXY_SCOPES", test.envValue)
		// act
		actual := getScopes()
		// assert
		if !arraysAreEqual(actual, test.expected) {
			t.Errorf("Test %s: expected %v, got %v", test.name, verboseString(test.expected), verboseString(actual))
		}
	}
}

// See empty elements in string
func verboseString(m []string) string {
	b := strings.Builder{}
	b.WriteString("[")
	for i, n := range m {
		q := fmt.Sprintf("\"%v\"", n)
		if i != 0 {
			q = "," + q
		}
		b.WriteString(q)
	}
	b.WriteString("]")
	return b.String()
}

func arraysAreEqual(m, n []string) bool {
	if len(m) != len(n) {
		return false
	}
	for k, v := range m {
		if n[k] != v {
			return false
		}
	}
	return true
}

func mapsAreEqual(m, n map[string]string) bool {
	if len(m) != len(n) {
		return false
	}
	for k, v := range m {
		if n[k] != v {
			return false
		}
	}
	return true
}
