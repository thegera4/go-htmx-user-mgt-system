package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/thegera4/go-htmx-user-mgt-system/pkg/handlers"
)

// Global variables
var db *sql.DB // This variable stores the database connection object
var tmpl *template.Template // This variable stores the parsed templates
var Store = sessions.NewCookieStore([]byte("usermanagementsecret")) // This variable stores the session

// This function is called before the main function.
func init() {
	// Parse and load all templates before starting the server
	tmpl = template.Must(template.ParseGlob("templates/*.html"))

	// Set up the session
	Store.Options = &sessions.Options{
		Path: "/",
		MaxAge: 3600 * 3, // 3 hours
		HttpOnly: true,
	}
}

// Creates a new connection to the database and stores it in the db variable
func initDB() {
	var err error

	// Open the database connection
	db, err = sql.Open("mysql", "root:toor@(127.0.0.1:3306)/usermanagement?parseTime=true") 
	if err != nil { log.Fatal(err) }

	// Check if the connection is successful
	if err = db.Ping(); err != nil { log.Fatal(err) }
}

func main() {
	initDB()
	defer db.Close()

	gRouter := mux.NewRouter()

	gRouter.HandleFunc("/", handlers.HomePage(db, tmpl, Store)).Methods("GET")

	gRouter.HandleFunc("/register", handlers.RegisterPage(db, tmpl)).Methods("GET")
	gRouter.HandleFunc("/register", handlers.RegisterHandler(db, tmpl)).Methods("POST")

	gRouter.HandleFunc("/login", handlers.LoginPage(db, tmpl)).Methods("GET")
	gRouter.HandleFunc("/login", handlers.LoginHandler(db, tmpl, Store)).Methods("POST")

	gRouter.HandleFunc("/edit", handlers.EditPage(db, tmpl, Store)).Methods("GET")
	gRouter.HandleFunc("/edit", handlers.UpdateProfileHandler(db, tmpl, Store)).Methods("POST")

	http.ListenAndServe(":8080", gRouter)
}

// This handler function sends a response to the root URL ("/")
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	err := tmpl.ExecuteTemplate(w, "home.html", nil)
	if err != nil { 
		http.Error(w, "Error while loading templates: " + err.Error(), http.StatusInternalServerError) 
	}
}