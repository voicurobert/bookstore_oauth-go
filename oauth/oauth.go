package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/voicurobert/bookstore_oauth-go/oauth/errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-ID"
	headerXCallerID = "X-Caller-ID"

	parameterAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

type oauthInterface interface {
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

func AuthenticateRequest(request *http.Request) *errors.RestError {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	atID := strings.TrimSpace(request.URL.Query().Get(parameterAccessToken))
	if atID == "" {
		return nil
	}
	at, err := getAccessToken(atID)
	if err != nil {
		return err
	}

	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))
	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)

}

func getAccessToken(atID string) (*accessToken, *errors.RestError) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", atID))
	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("invalid rest client response when trying to get access token")
	}
	if response.StatusCode > 299 {
		var restErr errors.RestError
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to get access token")
		}
		return nil, &restErr
	}
	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshal access token response")
	}
	return &at, nil
}
