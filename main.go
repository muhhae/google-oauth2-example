package main

import (
	"log"

	"github.com/joho/godotenv"
	"github.com/muhhae/learn-google-oauth2/auth"
	"github.com/muhhae/learn-google-oauth2/route"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Failed to load the env vars: %v", err)
	}

	authenticator, err := auth.NewGoogleAuthenticator()
	if err != nil {
		log.Fatalln(err.Error())
	}
	router := route.New(authenticator)
	log.Println("Starting server on http://localhost:8080")
	if err := router.Start("localhost:8080"); err != nil {
		log.Fatalln("Error starting server", err)
	}
}
