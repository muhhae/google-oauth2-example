package auth

import (
	"errors"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Authenticator struct {
	oauth2.Config
}

func NewGoogleAuthenticator() (*Authenticator, error) {
	clientId := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	clientRedirect := os.Getenv("CLIENT_REDIRECT")

	if clientId == "" || clientSecret == "" || clientRedirect == "" {
		return nil, errors.New("ENV CLIENT_ID, CLIENT_SECRET AND CLIENT_REDIRECT NOT SET")
	}

	conf := oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  clientRedirect,
		Endpoint:     google.Endpoint,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	}

	authenticator := &Authenticator{
		Config: conf,
	}

	return authenticator, nil
}
