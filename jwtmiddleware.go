package jwtmiddleware

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var (
	// ErrTokenNotFound is returned if the JWT can't be extracted from the request.
	ErrTokenNotFound = errors.New("Required authorization token not found")
	// ErrInvalidToken is returned if the JWT can't be parsed.
	ErrInvalidToken = errors.New("Token could not be parsed")
	// ErrInvalidSigningMethod is returned if the JWT specifies a different
	// signing algorithm than the expected one.
	ErrInvalidSigningMethod = errors.New("Token specifies an invalid signing algorithm")
	// ErrInvalidClaims is returned if the JWT claims fail to validate (e.g., the
	// token has expired).
	ErrInvalidClaims = errors.New("Token claims are invalid")
)

// ErrorHandler takes any errors that are returned while validating a JWT and
// is expected to handle it accordingly.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// TokenExtractor is a function that takes a request as input and returns
// either a token or an error.  An error should only be returned if an attempt
// to specify a token was found, but the information was somehow incorrectly
// formed.  In the case where a token is simply not present, this should not
// be treated as an error.  An empty string should be returned in that case.
type TokenExtractor func(r *http.Request) (string, error)

// Options is a struct for specifying configuration options for the middleware.
type Options struct {
	// The function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	ValidationKeyGetter jwt.Keyfunc
	// The name of the property in the request where the user information
	// from the JWT will be stored.
	// Default value: "user"
	UserProperty string
	// The function that will be called when there's an error validating the token
	// Default value: DefaultErrorHandler (returns 401 Unauthorized)
	ErrorHandler ErrorHandler
	// A boolean indicating if the credentials are required or not
	// Default value: false
	CredentialsOptional bool
	// A function that extracts the token from the request
	// Default: DefaultTokenExtractor (extracts from Authorization header as bearer token)
	Extractor TokenExtractor
	// Debug flag turns on debugging output
	// Default: false
	Debug bool
	// When set, all requests with the OPTIONS method will use authentication
	// Default: false
	EnableAuthOnOptions bool
	// When set, the middelware verifies that tokens are signed with the specific signing algorithm
	// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
	// Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
	// Default: nil
	SigningMethod jwt.SigningMethod
}

// JWTMiddleware represents the middleware, extracting the token and validating
// it before passing control to the next handler.
type JWTMiddleware struct {
	Options Options
}

// DefaultErrorHandler returns 401 Unauthorized with the reason in the body.
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}

// DefaultTokenExtractor extracts the JWT from the Authorization header.
// The header value is expected to be in the `bearer {token}` format.
func DefaultTokenExtractor(r *http.Request) (string, error) {
	authHeader, err := FromHeader("Authorization")(r)
	if err != nil {
		return "", nil // No error, just no token
	}

	// TODO: Make this a bit more robust, parsing-wise
	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", fmt.Errorf("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

// New constructs a new JWTMiddleware instance with supplied options.
func New(opts Options) *JWTMiddleware {
	if opts.UserProperty == "" {
		opts.UserProperty = "user"
	}

	if opts.ErrorHandler == nil {
		opts.ErrorHandler = DefaultErrorHandler
	}

	if opts.Extractor == nil {
		opts.Extractor = DefaultTokenExtractor
	}

	return &JWTMiddleware{
		Options: opts,
	}
}

func (m *JWTMiddleware) logf(format string, args ...interface{}) {
	if m.Options.Debug {
		log.Printf(format, args...)
	}
}

// Handler wraps the given HTTP handler with the JWT-validating middleware
func (m *JWTMiddleware) Handler(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let secure process the request. If it returns an error,
		// that indicates the request should not continue.
		token, err := m.checkJWT(w, r)

		// If there was an error, do not continue.
		if err != nil {
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), m.Options.UserProperty, token))
		h.ServeHTTP(w, r)
	})
}

// HandlerFunc wraps the given HTTP handler function with the JWT-validating middleware
func (m *JWTMiddleware) HandlerFunc(f func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return m.Handler(http.HandlerFunc(f))
}

// FromHeader returns a function that extracts the token from the specified
// HTTP header
func FromHeader(header string) TokenExtractor {
	return func(r *http.Request) (string, error) {
		return r.Header.Get(header), nil
	}
}

// FromParameter returns a function that extracts the token from the specified
// query string parameter
func FromParameter(param string) TokenExtractor {
	return func(r *http.Request) (string, error) {
		return r.URL.Query().Get(param), nil
	}
}

// FromFirst returns a function that runs multiple token extractors and takes the
// first token it finds
func FromFirst(extractors ...TokenExtractor) TokenExtractor {
	return func(r *http.Request) (string, error) {
		for _, ex := range extractors {
			token, err := ex(r)
			if err != nil {
				return "", err
			}
			if token != "" {
				return token, nil
			}
		}
		return "", nil
	}
}

func (m *JWTMiddleware) checkJWT(w http.ResponseWriter, r *http.Request) (*jwt.Token, error) {
	if !m.Options.EnableAuthOnOptions {
		if r.Method == "OPTIONS" {
			return nil, nil
		}
	}

	// Use the specified token extractor to extract a token from the request
	token, err := m.Options.Extractor(r)

	// If debugging is turned on, log the outcome
	if err != nil {
		m.logf("Error extracting JWT: %v", err)
	} else {
		m.logf("Token extracted: %s", token)
	}

	// If an error occurs, call the error handler and return an error
	if err != nil {
		m.Options.ErrorHandler(w, r, err)
		return nil, err
	}

	// If the token is empty...
	if token == "" {
		// Check if it was required
		if m.Options.CredentialsOptional {
			m.logf("  No credentials found (CredentialsOptional=true)")
			// No error, just no token (and that is ok given that CredentialsOptional is true)
			return nil, nil
		}

		// If we get here, the required token is missing
		m.Options.ErrorHandler(w, r, ErrTokenNotFound)
		m.logf("  Error: No credentials found (CredentialsOptional=false)")
		return nil, ErrTokenNotFound
	}

	// Now parse the token
	parsedToken, err := jwt.Parse(token, m.Options.ValidationKeyGetter)

	// Check if there was an error in parsing...
	if err != nil {
		m.logf("Error parsing token: %v", err)
		m.Options.ErrorHandler(w, r, ErrInvalidToken)
		return nil, ErrInvalidToken
	}

	if m.Options.SigningMethod != nil && m.Options.SigningMethod.Alg() != parsedToken.Header["alg"] {
		message := fmt.Sprintf("Expected %s signing method but token specified %s",
			m.Options.SigningMethod.Alg(),
			parsedToken.Header["alg"])
		m.logf("Error validating token algorithm: %s", message)
		m.Options.ErrorHandler(w, r, ErrInvalidSigningMethod)
		return nil, ErrInvalidSigningMethod
	}

	// Check if the parsed token is valid...
	if !parsedToken.Valid {
		m.logf("Token is invalid")
		m.Options.ErrorHandler(w, r, ErrInvalidClaims)
		return nil, ErrInvalidClaims
	}

	m.logf("JWT: %v", parsedToken)

	return parsedToken, nil
}
