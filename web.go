package main

import (
	"code.google.com/p/go.crypto/bcrypt"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/go-martini/martini"
	"github.com/martini-contrib/sessions"
	_ "github.com/mattn/go-sqlite3"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	MEMORY_BUF    = 2 * 1024 * 1024   // 2MB
	MAX_FILE_SIZE = 100 * 1024 * 1024 // 100 MB
	DB_FILE       = "./database/fileshare.db"
	PORT          = "8080"
)

type User struct {
	ID    int
	Name  string
	Email string
	Role  string
}

type Entry struct {
	ID       int
	Filename string
	Data     []byte
	Hash     []byte
	URL      string
}

var UploadPageTemplate = template.Must(template.ParseFiles("./templates/upload.html"))

func DBConnect() *sql.DB {
	db, err := sql.Open("sqlite3", DB_FILE)
	if err != nil {
		log.Println(err)
	}
	return db
}

func DBSetup() error {
	db := DBConnect()
	defer db.Close()
	_, err := db.Exec(
		`CREATE TABLE IF NOT EXISTS files (id INTEGER NOT NULL PRIMARY KEY, hash BLOB NOT NULL UNIQUE, data BLOB, filename TEXT);
		CREATE TABLE IF NOT EXISTS users (id INTEGER NOT NULL PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL, password TEXT NOT NULL);`,
	)
	return err
}

func DBUsersCount(db *sql.DB) (int, error) {
	var rows_number int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&rows_number)
	return rows_number, err
}

func DBGetData(db *sql.DB, hash []byte) ([]byte, string, error) {
	file := struct {
		data     []byte
		fileName string
	}{}
	err := db.QueryRow("SELECT data, filename FROM files WHERE hash=?", hash).Scan(&file.data, &file.fileName)
	return file.data, file.fileName, err
}

func DBGetFilesList(db *sql.DB, r *http.Request) []Entry {
	entry := Entry{}
	list := []Entry{}

	rows, err := db.Query("SELECT id, filename, hash FROM files ORDER BY id DESC")
	if err != nil {
		log.Println(err)
	}
	defer rows.Close()
	for rows.Next() {
		rows.Scan(&entry.ID, &entry.Filename, &entry.Hash)
		entry.URL = fmt.Sprintf("https://%s/%x", r.Host, entry.Hash)
		list = append(list, entry)
	}
	return list

}

func DBCreateEntry(db *sql.DB, hash []byte, data []byte, filename string) error {
	_, err := db.Exec("INSERT INTO files (hash, data, filename) VALUES (?, ?, ?)", hash, data, filename)
	return err
}


func DBDeleteEntryByID(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM files WHERE id=?", id)
	return err
}

func GenerateRandomHash() []byte {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	hash := md5.Sum([]byte(fmt.Sprintf("%d", time.Now().Unix()+r.Int63())))
	return hash[:] // make []byte from [16]byte
}

// Handlers

func ServeFile(w http.ResponseWriter, r *http.Request, db *sql.DB, params martini.Params) {

	if params["URL"] == "upload" {
		http.Redirect(w, r, "/upload", http.StatusMovedPermanently)
		return
	}
	log.Println(params["URL"])
	hash, err := hex.DecodeString(params["URL"])
	if err != nil {
		log.Println(err)
		http.NotFound(w, r)
		return
	}
	log.Println(hash)

	data, filename, err := DBGetData(db, hash)
	if err != nil {
		log.Println(err)
		http.NotFound(w, r)
		return
	}

	contentType := http.DetectContentType(data)
	log.Println(contentType)

	header := w.Header()
	// header.Set("Content-Disposition", "attachment;filename=\"test1.txt\"")
	header.Set("Content-Type", contentType)
	header.Set("Content-Disposition", "filename=\""+filename+"\"")
	log.Println(header)

	w.Write(data)
}

func ShowUploadPage(w http.ResponseWriter, r *http.Request, user *User, db *sql.DB) {
	if user.Email == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
	// log.Println(r.Header)

	entries := DBGetFilesList(db, r)
	data := struct {
		Entries []Entry
	}{
		Entries: entries,
	}
	err := UploadPageTemplate.ExecuteTemplate(w, "upload.html", data)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusNotFound)
	}
}

func UploadFile(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if err := r.ParseMultipartForm(MEMORY_BUF); err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusForbidden)
	}

	for key, value := range r.MultipartForm.Value {
		fmt.Fprintf(w, "%s:%s ", key, value)
		log.Printf("%s:%s", key, value)
	}

	for _, fileHeaders := range r.MultipartForm.File {
		for _, fileHeader := range fileHeaders {
			file, _ := fileHeader.Open()
			buf, _ := ioutil.ReadAll(file)
			hash := GenerateRandomHash()
			err := DBCreateEntry(db, hash, buf, fileHeader.Filename)
			if err != nil {
				log.Println(err)
			}
		}
	}

}

func UploadFromForm(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	file, header, err := r.FormFile("file")
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	defer file.Close()
	buf, _ := ioutil.ReadAll(file)
	hash := GenerateRandomHash()
	err = DBCreateEntry(db, hash, buf, header.Filename)
	if err != nil {
		log.Println(err)
	}
	// fmt.Fprintf(w, "%s ~> https://%s/%x", header.Filename, r.Host, hash)
	http.Redirect(w, r, "/upload", http.StatusFound)

}

func DeleteFiles(w http.ResponseWriter, r *http.Request, db *sql.DB, user *User) {
	if user.Email == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
	ids := r.FormValue("id")
	log.Println(ids)
	for _, id := range strings.Split(ids, ",") {
		int_id, err := strconv.Atoi(id)
		if err != nil {
			log.Println(err)
			continue
		} else {
			DBDeleteEntryByID(db, int_id)
		}

	}
	// http.Redirect(w, r, "/upload", http.StatusFound)
}

func Index(w http.ResponseWriter, r *http.Request) {
	page, err := ioutil.ReadFile("./static/html/index.html")
	if err != nil {
		log.Println(err)
		http.Error(w, "Cannot open file", http.StatusInternalServerError)
	}
	w.Write([]byte(page))
}

func ClassicMartiniWithoutLogging() *martini.ClassicMartini {
	r := martini.NewRouter()
	m := martini.New()
	m.Use(martini.Recovery())
	m.Use(martini.Static("static", martini.StaticOptions{Prefix: "/static/"}))
	m.MapTo(r, (*martini.Routes)(nil))
	m.Action(r.Handle)
	return &martini.ClassicMartini{m, r}
}

func ShowLoginPage(w http.ResponseWriter, r *http.Request, s sessions.Session, db *sql.DB, user *User) {
	users_count, err := DBUsersCount(db)
	if err != nil {
		log.Println(err)
	}
	if users_count < 1 {
		http.Redirect(w, r, "/signup", http.StatusFound)
	}
	s.Set("LoginError", "") // Remove error cookie after page was shown
	// err := LoginTemplates.ExecuteTemplate(w, "login.html", data)
	page, err := ioutil.ReadFile("./static/html/login.html")
	if err != nil {
		log.Println(err)
	}
	w.Write(page)
}

func SignUpGET(w http.ResponseWriter, r *http.Request) {
	page, err := ioutil.ReadFile("./static/html/signup.html")
	if err != nil {
		log.Println(err)
	}
	w.Write(page)
}

func SignUpPOST(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	name, email, pass := r.FormValue("name"), r.FormValue("email"), r.FormValue("pass")
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
	}
	_, err = db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", name, email, hashedPass)
	if err != nil {
		log.Println(err)
	}
	http.Redirect(w, r, "/upload", http.StatusFound)
}

func LogIn(w http.ResponseWriter, r *http.Request, db *sql.DB, s sessions.Session, user *User) {
	var (
		id             int
		hashedPassword string
	)

	email, pass := r.FormValue("email"), r.FormValue("pass")
	err := db.QueryRow("SELECT id, password FROM users WHERE email=?", email).Scan(&id, &hashedPassword)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			s.Set("LoginError", "Wrong e-mail or password!")
			http.Redirect(w, r, "/login", http.StatusFound)
		} else {
			log.Println(err)
			s.Set("LoginError", "Database error")
			http.Redirect(w, r, "/login", http.StatusFound)
		}
		return

	} else if bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(pass)) != nil {
		s.Set("LoginError", "Wrong e-mail or password!")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	s.Set("LoginError", "")
	s.Set("UserID", id)
	http.Redirect(w, r, "/upload", http.StatusFound)
}

func LogOut(w http.ResponseWriter, r *http.Request, s sessions.Session) {
	s.Delete("UserID")
	http.Redirect(w, r, "/", http.StatusFound)
}

func CheckIfLogged(w http.ResponseWriter, r *http.Request, s sessions.Session, db *sql.DB, c martini.Context) {
	user := &User{}
	err := db.QueryRow("SELECT username, email FROM users WHERE id=?",
		s.Get("UserID")).Scan(&user.Name, &user.Email)
	if err != nil {
		if err.Error() != "sql: no rows in result set" {
			log.Println(err)
		}
	}
	c.Map(user)
}

func main() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime)

	err := DBSetup()
	if err != nil {
		log.Println(err)
	}

	m := ClassicMartiniWithoutLogging()
	m.Map(DBConnect())

	store := sessions.NewCookieStore([]byte("mysecret"))
	m.Use(sessions.Sessions("fileshare", store))
	m.Use(CheckIfLogged)

	m.Get("/", Index)
	m.Get("/upload", ShowUploadPage)
	m.Post("/upload/v1/", UploadFile)
	m.Post("/upload", UploadFromForm)
	m.Delete("/upload", DeleteFiles)
	m.Get("/login(/*)", ShowLoginPage)
	m.Post("/login(/*)", LogIn)
	m.Get("/logout(/*)", LogOut)
	m.Get("/signup(/*)", SignUpGET)
	m.Post("/signup(/*)", SignUpPOST)
	m.Get("/:URL", ServeFile)

	// Start server
	host := os.Getenv("HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = PORT
	}
	bind := fmt.Sprintf("%s:%s", host, port)
	fmt.Printf("Listening on %s...\n", bind)
	log.Fatal(http.ListenAndServe(bind, m))
}
