package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

var remoteURLFlag = flag.String("remoteURL", "", "The remote host to proxy to.")
var remoteHostHeaderFlag = flag.String("remoteHostHeader", "", "The value of the 'Host' header to apply to outbound requests.")
var keysFlag = flag.String("keys", "", "The location of the JSON map containing issuers and their public keys.")
var portFlag = flag.String("port", "", "The port for the proxy to listen on.")
var healthCheckFlag = flag.String("health", "/health", "The path to the healthcheck endpoint.")
var prefixFlag = flag.String("prefix", "", "The prefix to strip from incoming requests applied to the remote URL, e.g to make /api/user?id=1 map to /user?id=1")
var scopesFlag = flag.String("scopes", "", "The scopes to validate from the token, defined as a comma delimmited string e.g. 'foo,moo'")

func main() {
	port, app, err := getApp()

	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	http.ListenAndServe(":"+port, app)
}

func getApp() (string, http.Handler, error) {
	flag.Parse()

	remoteURL, err := getRemoteURL()
	if err != nil {
		return "", nil, err
	}

	keys, err := getKeys(os.Environ())
	if err != nil {
		return "", nil, err
	}

	port, err := getPort()
	if err != nil {
		return "", nil, err
	}

	prefix := getPrefix()

	scopes := getScopes()

	remoteHostHeader := getRemoteHostHeader()

	proxy := NewReverseProxy(remoteURL, remoteHostHeader)

	// A request comes in to a load balancer of https://example.com/api/user?id=1
	// We've pointed it to the RemoteURL of https://api.example.org/
	// And we want to get https://api.example.org/user?id=1
	// The SingleHostReverseProxy doesn't strip the /api from the incoming request
	// So without rewriting the request, we'd actually get a request to https://api.example.org/api/user?id=1
	rewrite := NewRewriteHandler(prefix, proxy)

	// Wrap the proxy in authentication.
	auth := NewJWTAuthHandler(keys, scopes, rewrite)

	// Wrap the authentication in a health check (health checks don't need authentication).
	health := HealthCheckHandler{
		Path: getHealthCheckURI(),
		Next: auth,
	}

	// Wrap the health check in a logger.
	app := NewLoggingHandler(health)

	return port, app, nil
}

// NewReverseProxy creates a reverse proxy.
func NewReverseProxy(target *url.URL, hostHeader string) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
		// Override the host header.
		if hostHeader == "" {
			req.Host = target.Host
		} else {
			req.Host = hostHeader
		}
	}
	return &httputil.ReverseProxy{Director: director}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func getPort() (string, error) {
	port := *portFlag
	if port == "" {
		port = os.Getenv("JWTPROXY_LISTEN_PORT")
	}
	if port == "" {
		return "9090", errors.New("JWTPROXY_LISTEN_PORT environment variable or port command line flag not found")
	}
	return port, nil
}

func getRemoteURL() (*url.URL, error) {
	remoteURL := *remoteURLFlag
	if remoteURL == "" {
		remoteURL = os.Getenv("JWTPROXY_REMOTE_URL")
	}
	if remoteURL == "" {
		return nil, errors.New("JWTPROXY_REMOTE_URL environment variable or remoteURL command line flag not found")
	}
	u, err := url.Parse(remoteURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remoteURL %s with error %v", remoteURL, err)
	}
	return u, nil
}

func getKeys(environ []string) (map[string]string, error) {
	keys, err := getKeysFromEnvironment(environ)
	if err != nil {
		return keys, err
	}
	fromConfig, err := getKeysFromConfigFile()
	if err != nil {
		return fromConfig, err
	}
	for k, v := range fromConfig {
		keys[k] = v
	}
	return keys, nil
}

func getKeysFromEnvironment(environ []string) (map[string]string, error) {
	issuerPrefix := "JWTPROXY_ISSUER_"
	keyPrefix := "JWTPROXY_PUBLIC_KEY_"

	suffixToIssuerMap := make(map[string]string)
	suffixToKeyMap := make(map[string]string)

	for _, s := range environ {
		parts := strings.Split(s, "=")
		envName := parts[0]
		if strings.HasPrefix(envName, issuerPrefix) {
			suffix := envName[len(issuerPrefix):]
			suffixToIssuerMap[suffix] = parts[1]
		}
		if strings.HasPrefix(envName, keyPrefix) {
			suffix := envName[len(keyPrefix):]
			suffixToKeyMap[suffix] = parts[1]
		}
	}

	return zip(suffixToIssuerMap, suffixToKeyMap)
}

func zip(keys, values map[string]string) (map[string]string, error) {
	m := make(map[string]string)

	for suffix, issuer := range keys {
		value, ok := values[suffix]
		if !ok {
			return m, fmt.Errorf("could not find a matching JWTPROXY_PUBLIC_KEY_%s value for JWTPROXY_ISSUER_%s", suffix, suffix)
		}
		m[issuer] = value
	}

	return m, nil
}

func getKeysFromConfigFile() (map[string]string, error) {
	keys := make(map[string]string)
	configPath := os.Getenv("JWTPROXY_CONFIG")
	if configPath == "" {
		configPath = *keysFlag
	}
	if configPath == "" {
		return keys, nil
	}
	file, err := os.Open(configPath)
	defer file.Close()
	if err != nil {
		return keys, fmt.Errorf("Failed to open file %s with error %v", configPath, err)
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return keys, fmt.Errorf("Failed to read file %s with error %v", configPath, err)
	}
	err = json.Unmarshal(data, &keys)
	if err != nil {
		return keys, fmt.Errorf("Failed to parse JSON file %s with error %v", configPath, err)
	}
	return keys, nil
}

func getHealthCheckURI() string {
	hc := os.Getenv("JWTPROXY_HEALTHCHECK_URI")
	if hc == "" {
		return *healthCheckFlag
	}
	return hc
}

func getPrefix() string {
	prefix := *prefixFlag
	if prefix == "" {
		prefix = os.Getenv("JWTPROXY_PREFIX")
	}
	return prefix
}

func getRemoteHostHeader() string {
	h := *remoteHostHeaderFlag
	if h == "" {
		h = os.Getenv("JWTPROXY_REMOTE_HOST_HEADER")
	}
	return h
}

func getScopes() []string {
	s := *scopesFlag
	if s == "" {
		s = os.Getenv("JWTPROXY_SCOPES")
	}
	scopes := strings.Split(s, ",")
	filter(&scopes, "")
	return scopes
}

func filter(s *[]string, r string) {
	for i, e := range *s {
		if e == r {
			*s = append((*s)[:i], (*s)[i+1:]...)
		}
	}
}
