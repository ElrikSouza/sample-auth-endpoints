package authendpoints

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	ACCESS_TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
	USER_ENDPOINT         = "https://api.github.com/user"
)

type UserDataHandler interface {
	handleUser() error
}

type ShortGithubUser struct {
	Name string `json:"name"`
	Id   int    `json:"id"`
}

type GitAuthService struct {
	httpClient   *http.Client
	clientId     string
	clientSecret string
	callbackUrl  string
}

func NewGithubAuthService(httpClient *http.Client, clientId, clientSecret, callbackUrl string) *GitAuthService {
	return &GitAuthService{
		httpClient,
		clientId,
		clientSecret,
		callbackUrl,
	}
}

type githubAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

func (g *GitAuthService) GetLoginUrl() string {
	redirectUrl := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s", g.clientId, g.callbackUrl)
	return redirectUrl
}

func (g *GitAuthService) GetUserGitInfo(callbackCode string) (ShortGithubUser, error) {
	var user ShortGithubUser

	body := map[string]string{
		"client_id":     g.clientId,
		"client_secret": g.clientSecret,
		"code":          callbackCode,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return user, err
	}
	buff := bytes.NewBuffer(jsonBody)

	req, err := http.NewRequest("POST", ACCESS_TOKEN_ENDPOINT, buff)
	if err != nil {
		return user, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := g.httpClient.Do(req)
	if err != nil {
		return user, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return user, err
	}
	var finalBody githubAccessTokenResponse
	err = json.Unmarshal(resBytes, &finalBody)
	if err != nil {
		return user, err
	}

	authHeader := fmt.Sprintf("token %s", finalBody.AccessToken)
	req, err = http.NewRequest("GET", USER_ENDPOINT, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", authHeader)

	res, err = g.httpClient.Do(req)
	if err != nil {
		return user, err
	}
	resBytes, err = io.ReadAll(res.Body)
	if err != nil {
		return user, err
	}

	err = json.Unmarshal(resBytes, &user)
	if err != nil {
		return user, err
	}

	return user, nil
}
