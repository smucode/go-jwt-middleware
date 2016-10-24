package jwtmiddleware

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

// defaultAuthorizationHeaderName is the default header name where the Auth
// token should be written
const defaultAuthorizationHeaderName = "Authorization"

// envVarClientSecretName the environment variable to read the JWT environment
// variable
const envVarClientSecretName = "CLIENT_SECRET_VAR_SHHH"

// userPropertyName is the property name that will be set in the request context
const userPropertyName = "custom-user-property"

// the bytes read from the keys/sample-key file
// private key generated with http://kjur.github.io/jsjws/tool_jwt.html
var privateKey []byte = nil

// TestUnauthenticatedRequest will perform requests with no Authorization header
func TestUnauthenticatedRequest(t *testing.T) {
	testCases := []struct {
		method         string
		path           string
		expectedStatus int
	}{
		{"GET", "/", http.StatusOK},
		{"GET", "/protected", http.StatusUnauthorized},
	}
	for _, testCase := range testCases {
		w := makeUnauthenticatedRequest(testCase.method, testCase.path)
		if w.Code != testCase.expectedStatus {
			t.Errorf("expected status [%#v], got [%#v]", testCase.expectedStatus, w.Code)
		}
	}
}

// TestUnauthenticatedRequest will perform requests with no Authorization header
func TestAuthenticatedRequest(t *testing.T) {
	var e error
	privateKey, e = readPrivateKey()
	if e != nil {
		panic(e)
	}

	testCases := []struct {
		method         string
		path           string
		algorithm      jwt.SigningMethod
		expectedStatus int
		expectedBody   string
	}{
		// unprotected
		{"GET", "/", nil, http.StatusOK, ""},
		// protected
		{"GET", "/protected", nil, http.StatusOK, `{"text":"bar"}`},
		{"GET", "/protected", jwt.SigningMethodHS256, http.StatusOK, `{"text":"bar"}`},
		// protected but wrong expected algorithm
		{"GET", "/protected", jwt.SigningMethodRS256, http.StatusUnauthorized, "Expected RS256 signing method but token specified HS256"},
	}

	for _, testCase := range testCases {
		w := makeAuthenticatedRequest(testCase.method, testCase.path, map[string]interface{}{"foo": "bar"}, testCase.algorithm)
		if w.Code != testCase.expectedStatus {
			t.Errorf("expected status [%#v], got [%#v]", testCase.expectedStatus, w.Code)
		}

		responseBytes, err := ioutil.ReadAll(w.Body)
		if err != nil {
			panic(err)
		}
		responseBody := strings.TrimSpace(string(responseBytes))
		if responseBody != testCase.expectedBody {
			t.Errorf("expected body [%#v], got [%#v]", testCase.expectedBody, responseBody)
		}
	}
}

func makeUnauthenticatedRequest(method string, url string) *httptest.ResponseRecorder {
	return makeAuthenticatedRequest(method, url, nil, nil)
}

func makeAuthenticatedRequest(method string, url string, c map[string]interface{}, expectedSignatureAlgorithm jwt.SigningMethod) *httptest.ResponseRecorder {
	r, _ := http.NewRequest(method, url, nil)
	if c != nil {
		token := jwt.New(jwt.SigningMethodHS256)
		token.Claims = jwt.MapClaims(c)
		// private key generated with http://kjur.github.io/jsjws/tool_jwt.html
		s, e := token.SignedString(privateKey)
		if e != nil {
			panic(e)
		}
		r.Header.Set(defaultAuthorizationHeaderName, fmt.Sprintf("bearer %v", s))
	}
	w := httptest.NewRecorder()
	n := createRouter(expectedSignatureAlgorithm)
	n.ServeHTTP(w, r)
	return w
}

func createRouter(expectedSignatureAlgorithm jwt.SigningMethod) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)

	jwtMiddleware := JWT(expectedSignatureAlgorithm)
	mux.Handle("/protected", jwtMiddleware.Handler(http.HandlerFunc(protectedHandler)))

	return mux
}

// JWT creates the middleware that parses a JWT encoded token
func JWT(expectedSignatureAlgorithm jwt.SigningMethod) *JWTMiddleware {
	return New(Options{
		Debug:               false,
		CredentialsOptional: false,
		UserProperty:        userPropertyName,
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			if privateKey == nil {
				var err error
				privateKey, err = readPrivateKey()
				if err != nil {
					panic(err)
				}
			}
			return privateKey, nil
		},
		SigningMethod: expectedSignatureAlgorithm,
	})
}

// readPrivateKey will load the keys/sample-key file into the
// global privateKey variable
func readPrivateKey() ([]byte, error) {
	privateKey, e := ioutil.ReadFile("keys/sample-key")
	return privateKey, e
}

// indexHandler will return an empty 200 OK response
func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// protectedHandler will return the content of the "foo" encoded data
// in the token as json -> {"text":"bar"}
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	u := r.Context().Value(userPropertyName)
	user := u.(*jwt.Token)
	respondJson(user.Claims.(jwt.MapClaims)["foo"].(string), w)
}

// Response quick n' dirty Response struct to be encoded as json
type Response struct {
	Text string `json:"text"`
}

// respondJson will take an string to write through the writer as json
func respondJson(text string, w http.ResponseWriter) {
	response := Response{text}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}
