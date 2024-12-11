package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"gitlab.com/wit-id/test-mysql/src/authentication"
	healthcheck "gitlab.com/wit-id/test-mysql/src/health_check"
)

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/", healthcheck.HealthCheck)
	r.HandleFunc("/auth/v3/register", authentication.Register)
	r.HandleFunc("/auth/v3/verify", authentication.Verify)
	r.HandleFunc("/auth/v3/login", authentication.Login)
	r.HandleFunc("/auth/v3/change", authentication.ChangePassword)
	r.HandleFunc("/auth/v3/forgot", authentication.ForgotPassword)
	r.HandleFunc("/auth/v3/resend", authentication.ResendMail)
	r.HandleFunc("/auth/v3/social/completition", authentication.SocialCompletition)

	s := &http.Server{
		ReadHeaderTimeout: 2 * time.Minute,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		Addr:              ":5000",
		Handler:           r,
	}

	log.Fatal(s.ListenAndServe())
}
