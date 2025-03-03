package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/namsral/flag"
	"github.com/sirupsen/logrus"
)

// Vars
var fw *ForwardAuth
var log logrus.FieldLogger

// Primary handler
func handler(w http.ResponseWriter, r *http.Request) {
	// Logging setup
	logger := log.WithFields(logrus.Fields{
		"SourceIP": r.Header.Get("X-Forwarded-For"),
	})
	logger.WithFields(logrus.Fields{
		"Headers": r.Header,
	}).Debugf("Handling request")

	// Parse uri
	uri, err := url.Parse(r.Header.Get("X-Forwarded-Uri"))
	if err != nil {
		logger.Errorf("Error parsing X-Forwarded-Uri, %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Handle callback
	if uri.Path == fw.Path {
		logger.Debugf("Passing request to auth callback")
		handleCallback(w, r, uri.Query(), logger)
		return
	}

	// Get auth cookie
	c, err := r.Cookie(fw.CookieName)
	if err != nil {
		// Error indicates no cookie, generate nonce
		err, nonce := fw.Nonce()
		if err != nil {
			logger.Errorf("Error generating nonce, %v", err)
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Set the CSRF cookie
		http.SetCookie(w, fw.MakeCSRFCookie(r, nonce))
		logger.Debug("Set CSRF cookie and redirecting to oidc login")
		logger.Debugf("uri.Path was %s", uri.Path)
		logger.Debugf("fw.Path was %s", fw.Path)

		// Forward them on
		http.Redirect(w, r, fw.GetLoginURL(r, nonce), http.StatusTemporaryRedirect)

		return
	}

	// Validate cookie
	valid, email, err := fw.ValidateCookie(r, c)
	if !valid {
		logger.Errorf("Invalid cookie: %v", err)
		http.Error(w, "Not authorized", 401)
		return
	}

	// Validate user
	valid = fw.ValidateEmail(email)
	if !valid {
		logger.WithFields(logrus.Fields{
			"email": email,
		}).Errorf("Invalid email")
		http.Error(w, "Not authorized", 401)
		return
	}

	// Valid request
	logger.Debugf("Allowing valid request ")
	w.Header().Set("X-Forwarded-User", email)
	w.WriteHeader(200)
}

// Authenticate user after they have come back from oidc
func handleCallback(w http.ResponseWriter, r *http.Request, qs url.Values,
	logger logrus.FieldLogger) {
	// Check for CSRF cookie
	csrfCookie, err := r.Cookie(fw.CSRFCookieName)
	if err != nil {
		logger.Warn("Missing csrf cookie")
		http.Error(w, "Not authorized", 401)
		return
	}

	// Validate state
	state := qs.Get("state")
	valid, redirect, err := fw.ValidateCSRFCookie(csrfCookie, state)
	if !valid {
		logger.WithFields(logrus.Fields{
			"csrf":  csrfCookie.Value,
			"state": state,
		}).Warnf("Error validating csrf cookie: %v", err)
		http.Error(w, "Not authorized", 401)
		return
	}

	// Clear CSRF cookie
	http.SetCookie(w, fw.ClearCSRFCookie(r))

	// Exchange code for token
	token, err := fw.ExchangeCode(r, qs.Get("code"))
	if err != nil {
		logger.Errorf("Code exchange failed with: %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Validate token
	err = fw.ValidateToken(token, fw.redirectUri(r))
	if err != nil {
		logger.Warnf("Failed to validate token: %v", err)
		http.Error(w, "Bad token", 403)
		return
	}

	// Get user
	user, err := fw.GetUser(token)
	if err != nil {
		logger.Errorf("Error getting user: %s", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Generate cookie
	http.SetCookie(w, fw.MakeCookie(r, user.Email))
	logger.WithFields(logrus.Fields{
		"user": user.Email,
	}).Infof("Generated auth cookie")

	// Redirect
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

func getOidcConfig(oidc string) map[string]interface{} {
	uri, err := url.Parse(oidc)
	if err != nil {
		log.Fatal("failed to parse oidc string")
	}
	uri.Path = path.Join(uri.Path, "/.well-known/openid-configuration")
	res, err := http.Get(uri.String())
	if err != nil {
		log.Fatal("failed to get oidc parametere from oidc connect")
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal("failed to read response body")
	}
	var result map[string]interface{}
	json.Unmarshal(body, &result)
	log.Debug(result)
	return result
}

// Main
func main() {
	// Parse options
	flag.String(flag.DefaultConfigFlagname, "", "Path to config file")
	path := flag.String("url-path", "_oauth", "Callback URL")
	lifetime := flag.Int("lifetime", 43200, "Session length in seconds")
	secret := flag.String("secret", "", "*Secret used for signing (required)")
	authHost := flag.String("auth-host", "", "Central auth login")
	oidcIssuer := flag.String("oidc-issuer", "", "OIDC Issuer URL (required)")
	clientId := flag.String("client-id", "", "Client ID (required)")
	clientSecret := flag.String("client-secret", "", "Client Secret (required)")
	cookieName := flag.String("cookie-name", "_forward_auth", "Cookie Name")
	cSRFCookieName := flag.String("csrf-cookie-name", "_forward_auth_csrf", "CSRF Cookie Name")
	cookieDomainList := flag.String("cookie-domains", "", "Comma separated list of cookie domains") //todo
	cookieSecret := flag.String("cookie-secret", "", "Deprecated")
	cookieSecure := flag.Bool("cookie-secure", true, "Use secure cookies")
	domainList := flag.String("domain", "", "Comma separated list of email domains to allow")
	emailWhitelist := flag.String("whitelist", "", "Comma separated list of emails to allow")
	prompt := flag.String("prompt", "", "Space separated list of OpenID prompt options")
	logLevel := flag.String("log-level", "warn", "Log level: trace, debug, info, warn, error, fatal, panic")
	logFormat := flag.String("log-format", "text", "Log format: text, json, pretty")
	roleAuthFile := flag.String("role-auth-file", "", "Role auth config file path")

	flag.Parse()

	// Setup logger
	log = CreateLogger(*logLevel, *logFormat)

	// Backwards compatibility
	if *secret == "" && *cookieSecret != "" {
		*secret = *cookieSecret
	}

	// Check for show stopper errors
	if *clientId == "" || *clientSecret == "" || *secret == "" || *oidcIssuer == "" {
		log.Fatal("client-id, client-secret, secret and oidc-issuer must all be set")
	}

	var oidcParams = getOidcConfig(*oidcIssuer)

	loginUrl, err := url.Parse((oidcParams["authorization_endpoint"].(string)))
	if err != nil {
		log.Fatal("unable to parse login url")
	}

	tokenUrl, err := url.Parse((oidcParams["token_endpoint"].(string)))
	if err != nil {
		log.Fatal("unable to parse token url")
	}
	userUrl, err := url.Parse((oidcParams["userinfo_endpoint"].(string)))
	if err != nil {
		log.Fatal("unable to parse user url")
	}

	// Parse lists
	var cookieDomains []CookieDomain
	if *cookieDomainList != "" {
		for _, d := range strings.Split(*cookieDomainList, ",") {
			cookieDomain := NewCookieDomain(d)
			cookieDomains = append(cookieDomains, *cookieDomain)
		}
	}

	var domain []string
	if *domainList != "" {
		domain = strings.Split(*domainList, ",")
	}
	var whitelist []string
	if *emailWhitelist != "" {
		whitelist = strings.Split(*emailWhitelist, ",")
	}

	// Load role auth
	var roleConfig map[string][]string
	roleConfigPtr := &roleConfig
	if *roleAuthFile != "" {
		fileBytes, err := ioutil.ReadFile(*roleAuthFile)
		if err != nil {
			log.Fatalf("Failed to read role auth config file %s: %v", *roleAuthFile, err)
		}
		err = json.Unmarshal(fileBytes, roleConfigPtr)
		if err != nil {
			log.Fatalf("Failed to deserialise role auth config file: %v", err)
		}
	} else {
		roleConfigPtr = nil
	}

	// Setup
	fw = &ForwardAuth{
		Path:     fmt.Sprintf("/%s", *path),
		Lifetime: time.Second * time.Duration(*lifetime),
		Secret:   []byte(*secret),
		AuthHost: *authHost,

		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Scope:        "openid profile email",

		LoginURL: loginUrl,
		TokenURL: tokenUrl,
		UserURL:  userUrl,

		CookieName:     *cookieName,
		CSRFCookieName: *cSRFCookieName,
		CookieDomains:  cookieDomains,
		CookieSecure:   *cookieSecure,

		Domain:    domain,
		Whitelist: whitelist,

		Prompt: *prompt,

		RoleConfig: roleConfigPtr,
	}

	// Attach handler
	http.HandleFunc("/", handler)

	// Start
	jsonConf, _ := json.Marshal(fw)
	log.Debugf("Starting with options: %s", string(jsonConf))
	log.Info("Listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}
