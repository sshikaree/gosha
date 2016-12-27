package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

func SetupDB() {
	var err error
	DB, err = sql.Open("sqlite3", DB_FILE)
	if err != nil {
		log.Fatal(err)
	}
	_, err = DB.Exec(
		`CREATE TABLE IF NOT EXISTS files 
        (id INTEGER NOT NULL PRIMARY KEY, hash BLOB NOT NULL UNIQUE, data BLOB, filename TEXT, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL);
		CREATE TABLE IF NOT EXISTS users 
        (id INTEGER NOT NULL PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions
        (id INTEGER NOT NULL PRIMARY KEY, session_hash BLOB NOT NULL UNIQUE, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
	)
	if err != nil {
		log.Fatal(err)
	}
	// Create default user admin|admin if not exists
	rows_num := 0
	err = DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&rows_num)
	if err != nil {
		log.Fatal(err)
	}
	if rows_num == 0 {
		passwdHash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}
		_, err = DB.Exec(
			"INSERT INTO users (username, email, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
			"admin", "", passwdHash, "admin", time.Now().Unix(),
		)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func CreateUser(u *User) error {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = DB.Exec(
		"INSERT INTO users (username, email, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
		u.Name, u.Email, hashedPass, "admin", time.Now().Unix(),
	)
	return err
}

func UpdateUser(u *User) error {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = DB.Exec(
		"UPDATE users SET username=?, email=?, password=? WHERE id=?",
		u.Name, u.Email, hashedPass, u.ID,
	)
	return err
}

func GetUserByName(username string) (*User, error) {
	u := new(User)
	err := DB.QueryRow(
		"SELECT id, username, email, password, role FROM users WHERE username=?", username,
	).Scan(&u.ID, &u.Name, &u.Email, &u.Password, &u.Role)
	return u, err
}

func CreateEntry(hash []byte, data []byte, filename string, u *User) error {
	_, err := DB.Exec(
		"INSERT INTO files (hash, data, filename, user_id, created_at) VALUES (?, ?, ?, ?, ?)",
		hash, data, filename, u.ID, time.Now().Unix(),
	)
	return err
}

func DeleteEntryByID(id uint64) error {
	_, err := DB.Exec("DELETE FROM files WHERE id=?", id)
	return err
}

func GetSessionUser(sessionHash []byte) (*User, error) {
	u := new(User)
	err := DB.QueryRow(
		"SELECT id, username, email, role FROM users WHERE id=(SELECT user_id FROM SESSIONS WHERE session_hash=?)", sessionHash,
	).Scan(&u.ID, &u.Name, &u.Email, &u.Role)

	return u, err
}

func GetFile(r *http.Request, hash []byte) (*Entry, error) {
	file := new(Entry)
	err := DB.QueryRow(
		"SELECT id, hash, data, filename FROM files WHERE hash=?", hash,
	).Scan(&file.ID, &file.Hash, &file.Data, &file.Filename)
	file.URL = fmt.Sprintf("http://%s/%x", r.Host, hash)
	return file, err
}

func GetUserFilesList(r *http.Request, u *User) []Entry {
	entry := Entry{}
	list := []Entry{}

	rows, err := DB.Query(
		"SELECT id, filename, hash, created_at FROM files WHERE user_id=? ORDER BY id DESC",
		u.ID,
	)
	if err != nil {
		log.Println(err)
	}
	defer rows.Close()
	for rows.Next() {
		rows.Scan(&entry.ID, &entry.Filename, &entry.Hash, &entry.CreatedAt)
		entry.URL = fmt.Sprintf("http://%s/%x", r.Host, entry.Hash)
		list = append(list, entry)
	}
	return list

}

func DeleteSessionFromDB(sessionHash []byte) error {
	_, err := DB.Exec("DELETE FROM sessions WHERE session_hash=?", sessionHash)
	return err
}

func CreateSessionInDB(sessionHash []byte, user *User) error {
	_, err := DB.Exec(
		"INSERT INTO sessions (session_hash, user_id, created_at) VALUES (?, ?, ?)",
		sessionHash, user.ID, time.Now().Unix(),
	)
	return err
}

// Sessions clean up goroutine
func SessionCleaner() {
	for {
		_, err := DB.Exec("DELETE FROM sessions WHERE created_at < ?", time.Now().Unix()-SESSION_MAX_AGE)
		if err != nil {
			log.Println(err)
		}
		time.Sleep(time.Second * 300)
	}
}
