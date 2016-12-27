package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func HashToString(hash []byte) string {
	return fmt.Sprintf("%x", hash)
}

const (
	MEMORY_BUF    = 2 * 1024 * 1024   // 2MB
	MAX_FILE_SIZE = 100 * 1024 * 1024 // 100 MB
	DB_FILE       = "./database/fileshare.db"
	PORT          = "8080"
)

var tmpls = template.Must(template.ParseGlob("./templates/*.html"))

func GenerateRandomHash() []byte {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	hash := md5.Sum([]byte(fmt.Sprintf("%d", time.Now().Unix()+r.Int63())))
	return hash[:] // make []byte from [16]byte
}

// Handlers

func ServeFile(w http.ResponseWriter, r *http.Request) {
	hash, err := hex.DecodeString(strings.Replace(r.URL.Path, "/", "", -1))
	if err != nil {
		log.Println(err)
		http.NotFound(w, r)
		return
	}
	log.Println(hash)

	f, err := GetFile(r, hash)
	if err != nil {
		// log.Println(err)
		http.NotFound(w, r)
		return
	}

	contentType := http.DetectContentType(f.Data)
	log.Println(contentType)

	header := w.Header()
	// header.Set("Content-Disposition", "attachment;filename=\"test1.txt\"")
	header.Set("Content-Type", contentType)
	header.Set("Content-Disposition", "filename=\""+f.Filename+"\"")
	log.Println(header)

	w.Write(f.Data)
}

func ShowUploadPage(w http.ResponseWriter, r *http.Request) {
	user := checkSession(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	entries := GetUserFilesList(r, user)
	data := struct {
		Entries []Entry
		User    *User
	}{
		Entries: entries,
		User:    user,
	}
	err := tmpls.ExecuteTemplate(w, "upload.html", data)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
}

func UploadFile(w http.ResponseWriter, r *http.Request) {
	user := checkSession(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseMultipartForm(MEMORY_BUF); err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
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
			err := CreateEntry(hash, buf, fileHeader.Filename, user)
			if err != nil {
				log.Println(err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
}

func UploadFromForm(w http.ResponseWriter, r *http.Request) {
	user := checkSession(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	defer file.Close()
	buf, _ := ioutil.ReadAll(file)
	hash := GenerateRandomHash()
	err = CreateEntry(hash, buf, header.Filename, user)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// fmt.Fprintf(w, "%s ~> https://%s/%x", header.Filename, r.Host, hash)
	http.Redirect(w, r, "/upload", http.StatusFound)
	return
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		ShowUploadPage(w, r)
	case "POST":
		UploadFromForm(w, r)
	case "DELETE":
		DeleteFiles(w, r)
	}
}

func DeleteFiles(w http.ResponseWriter, r *http.Request) {
	user := checkSession(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	ids := r.FormValue("id")
	log.Println(ids)
	for _, id := range strings.Split(ids, ",") {
		int_id, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			log.Println(err)
			continue
		} else {
			DeleteEntryByID(int_id)
		}
	}
	// http.Redirect(w, r, "/upload", http.StatusFound)
}

func Index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		ServeFile(w, r)
		return
	}
	http.ServeFile(w, r, "./static/html/index.html")

}

func getSignUp(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/html/signup.html")
}

func postSignUp(w http.ResponseWriter, r *http.Request) {
	u := new(User)
	u.Name, u.Email, u.Password = r.FormValue("name"), r.FormValue("email"), r.FormValue("pass")
	if err := CreateUser(u); err != nil {
		// w.Write([]byte("Error: " + err.Error()))
		// http.Redirect(w, r, "/signup", http.StatusInternalServerError)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/upload", http.StatusFound)
	return
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		getSignUp(w, r)
	case "POST":
		postSignUp(w, r)
	}
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/html/login.html")
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	username, pass := r.FormValue("name"), r.FormValue("pass")
	user, err := GetUserByName(username)
	if err != nil {
		// log.Println(err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass)) != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	err = StartSession(w, user)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/upload", http.StatusFound)
	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		getLogin(w, r)
	case "POST":
		postLogin(w, r)
	}
}

func logOut(w http.ResponseWriter, r *http.Request) {
	err := DeleteSession(w, r)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
	return
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		getUserPage(w, r)
	case "POST":
		postUserPage(w, r)
	}
}

func getUserPage(w http.ResponseWriter, r *http.Request) {
	user := checkSession(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	tmpls.ExecuteTemplate(w, "user.html", user)
}

func postUserPage(w http.ResponseWriter, r *http.Request) {
	user := checkSession(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	user.Name, user.Email, user.Password = r.FormValue("name"), r.FormValue("email"), r.FormValue("pass")
	if err := UpdateUser(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	http.Redirect(w, r, "/upload", http.StatusFound)
	return
}

func main() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime)

	SetupDB()
	defer DB.Close()

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logOut)
	// Implement later
	// http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/user", userHandler)

	http.HandleFunc("/", Index)

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

	go SessionCleaner()

	log.Fatal(http.ListenAndServe(bind, nil))
}
