package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Ibrahimkazi18/GoLoginPortal/utils"
)

// Login data
type Login struct {
	HashPassword string
	SessionToken string
	CSRFToken    string
}

// key is username
var users = map[string]Login{}

func main() {
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)

	http.ListenAndServe("localhost:8000", nil)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		err := http.StatusMethodNotAllowed
		http.Error(w, "Invalid method", err)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(username) < 8 || len(password) < 8 {
		err := http.StatusNotAcceptable
		http.Error(w, "Username and Password should be greater than 8", err)
		return
	}

	if _, ok := users[username]; ok {
		err := http.StatusConflict
		http.Error(w, "username already exists", err)
		return
	}

	hashedPassword, _ := utils.CreateHashPassword(password)
	users[username] = Login{
		HashPassword: hashedPassword,
		SessionToken: "",
		CSRFToken:    "",
	}

	fmt.Fprintln(w, "User registered Successfully")
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		err := http.StatusMethodNotAllowed
		http.Error(w, "Invalid method", err)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok || !utils.CheckPasswordHash(password, user.HashPassword) {
		err := http.StatusConflict
		http.Error(w, "Invalid username or password", err)
		return
	}

	sessionToken := utils.GenerateToken(16)
	csrfToken := utils.GenerateToken(16)

	//set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	//set csrf token in a cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false, //Needs to be accessible to the client side
	})

	//storing sessiontoken in database
	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	fmt.Fprintf(w, "Login Successful!")
}

func protected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		err := http.StatusMethodNotAllowed
		http.Error(w, "Invalid method", err)
		return
	}

	username := r.FormValue("username")

	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, err.Error(), er)
		return
	}

	fmt.Fprintln(w, "CSRF validation successful, Welcome,", username)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, err.Error(), er)
		return
	}

	//clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	//clear from db
	username := r.FormValue("username")
	user := users[username]
	user.SessionToken = ""
	user.CSRFToken = ""
	users[username] = user

	fmt.Fprintln(w, "Logget Out Succesfully")
}
