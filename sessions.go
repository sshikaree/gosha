package main

import "net/http"
import "strings"
import "encoding/hex"
import "log"

const (
	SESSION_MAX_AGE = 3600 // 1 hour
)

func checkSession(r *http.Request) *User {
	sessionCookie, err := r.Cookie("session")
	if err != nil || strings.TrimSpace(sessionCookie.Value) == "" {
		return nil
	}
	sessionHash, err := hex.DecodeString(sessionCookie.Value)
	if err != nil {
		log.Println(err)
		return nil
	}
	user, err := GetSessionUser(sessionHash)
	if err != nil {
		log.Println(err)
		return nil
	}
	return user

}

func DeleteSession(w http.ResponseWriter, r *http.Request) error {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		return err
	}
	sessionHash, err := hex.DecodeString(sessionCookie.Value)
	if err != nil {
		return err
	}
	err = DeleteSessionFromDB(sessionHash)
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	return err
}

func StartSession(w http.ResponseWriter, user *User) error {
	sessionHash := GenerateRandomHash()
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  HashToString(sessionHash),
		Path:   "/",
		MaxAge: SESSION_MAX_AGE,
	})
	err := CreateSessionInDB(sessionHash, user)
	return err
}
