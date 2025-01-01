package main

import (
	"errors"
	"net/http"
)

func Authorize(r *http.Request) error {
	username := r.FormValue("username")

	user, ok := users[username]
	if !ok {
		return errors.New("user unauthorized")
	}

	//Get the session token from he cookie
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return errors.New("session unauthorized")
	}

	//Get the CSRF token from he cookie
	csrf := r.Header.Get("csrf_token")
	if csrf != user.CSRFToken || csrf == "" {
		return errors.New("csrf unauthorized")
	}

	return nil
}
