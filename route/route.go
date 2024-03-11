package route

import (
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/muhhae/learn-google-oauth2/auth"
	"github.com/muhhae/learn-google-oauth2/view"
	"golang.org/x/oauth2"
)

func New(a *auth.Authenticator) *echo.Echo {
	router := echo.New()
	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		log.Fatalln("ENV SESSION_SECRET NOT SET")
	}
	gob.Register(oauth2.Token{})

	sessionStore := sessions.NewCookieStore([]byte(sessionSecret))
	sessionStore.Options.HttpOnly = true

	router.Use(session.Middleware(sessionStore))

	router.GET("/login", loginHandler(a))
	router.GET("/auth", authHandler(a))
	router.GET("/", homeHandler())
	router.GET("/profile", profileHandler())

	return router
}

func loginHandler(a *auth.Authenticator) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		state := oauth2.GenerateVerifier()
		sess.Values["state"] = state
		err = sess.Save(c.Request(), c.Response())
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		loginUrl := a.AuthCodeURL(state)
		return c.Redirect(http.StatusTemporaryRedirect, loginUrl)
	}
}

func authHandler(a *auth.Authenticator) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		if c.QueryParam("state") != sess.Values["state"] {
			return c.String(http.StatusBadRequest, "Invalid State")
		}
		token, err := a.Exchange(c.Request().Context(), c.QueryParam("code"))
		if err != nil {
			return c.String(http.StatusUnauthorized, "Failed to authenticate")
		}
		sess.Values["token"] = token
		sess.Values["id_token"] = token.Extra("id_token")
		err = sess.Save(c.Request(), c.Response())
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		return c.Redirect(http.StatusTemporaryRedirect, "/profile")
	}
}

func homeHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		view.Home().Render(context.Background(), c.Response().Writer)
		return c.NoContent(http.StatusOK)
	}
}

func profileHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}

		storedToken := sess.Values["token"]
		if storedToken == nil {
			return c.String(http.StatusUnauthorized, "No session found please login first")
		}

		token := storedToken.(oauth2.Token)
		token.Valid()
		if token.Valid() == false {
			return c.String(http.StatusUnauthorized, "Your token has been expired, please login again")
		}
		accessToken := token.AccessToken
		response, err := http.Get("https://www.googleapis.com/oauth2/v1/userinfo?access_token=" + accessToken)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}

		if response.StatusCode != http.StatusOK {
			return c.String(http.StatusInternalServerError, "IDK")
		}

		defer response.Body.Close()
		b, err := io.ReadAll(response.Body)
		content := string(b)
		response, err = http.Get("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + accessToken)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}

		if response.StatusCode != http.StatusOK {
			return c.String(http.StatusInternalServerError, "IDK")
		}

		defer response.Body.Close()
		b, err = io.ReadAll(response.Body)
		content += string(b) + "\n"

		idToken := fmt.Sprint(sess.Values["id_token"])
		content += "ID TOKEN : " + idToken + "\n"

		return c.String(http.StatusOK, content)
	}
}
