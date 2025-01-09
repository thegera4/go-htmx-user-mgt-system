package handlers

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"
	"github.com/gorilla/sessions"
	"github.com/thegera4/go-htmx-user-mgt-system/pkg/models"
	"github.com/thegera4/go-htmx-user-mgt-system/pkg/repository"
	"golang.org/x/crypto/bcrypt"
)

// Returns/Loads the "register" template.
func RegisterPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl.ExecuteTemplate(w, "register", nil)
	}
}

// Registers a new user in the database and redirects to the login page.
func RegisterHandler(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		var errorMessages []string
		r.ParseForm() // Parse the form data

		user.Name = r.FormValue("name")
		user.Email = r.FormValue("email")
		user.Password = r.FormValue("password")
		user.Category, _ = strconv.Atoi(r.FormValue("category"))

		// Basic validation
		if user.Name == ""{
			errorMessages = append(errorMessages, "Name is required.")
		}
		if user.Email == ""{
			errorMessages = append(errorMessages, "Email is required.")
		}
		if user.Password == ""{
			errorMessages = append(errorMessages, "Password is required.")
		}

		if len(errorMessages) > 0 {
			tmpl.ExecuteTemplate(w, "autherrors", errorMessages)
			return
		}

		// Hash the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			errorMessages = append(errorMessages, "Failed to hash password.")
			tmpl.ExecuteTemplate(w, "autherrors", errorMessages)
			return
		}
		user.Password = string(hashedPassword)

		// Set default values
		user.DOB = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
		user.Bio = "Bio goes here"
		user.Avatar = ""

		// Create user in the database
		err = repository.CreateUser(db, user)
		if err != nil {
			errorMessages = append(errorMessages, "Failed to create user: " + err.Error())
			tmpl.ExecuteTemplate(w, "autherrors", errorMessages)
			return
		}

		// Set HTTP status code 204 (no content) and set 'HX-Location' header to signal HTMX to redirect
		w.Header().Set("HX-Location", "/login")
		w.WriteHeader(http.StatusNoContent)
	}
}

// Returns/Loads the "login" template.
func LoginPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl.ExecuteTemplate(w, "login", nil)
	}
}

// Logs a user to the system. Redirects to the profile page.
func LoginHandler(db *sql.DB, tmpl *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		email := r.FormValue("email")
		password := r.FormValue("password")

		var errorMessages []string

		// Basic validation
		if email == "" {
			errorMessages = append(errorMessages, "Email is required.")
		}
		if password == "" {
			errorMessages = append(errorMessages, "Password is required.")
		}

		if len(errorMessages) > 0 {
			tmpl.ExecuteTemplate(w, "autherrors", errorMessages)
			return
		}

		// Retrieve user by email
		user, err := repository.GetUserByEmail(db, email)
		if err != nil {
			if err == sql.ErrNoRows {
				errorMessages = append(errorMessages, "Invalid email or password")
				tmpl.ExecuteTemplate(w, "autherrors", errorMessages)
				return
			}

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Compare the hashed password from the DB with the provided password
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			errorMessages = append(errorMessages, "Invalid email or password")
			tmpl.ExecuteTemplate(w, "autherrors", errorMessages)

			return
		}

		// Create session and authenticate the user
		session, err := store.Get(r, "logged-in-user")
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		session.Values["user_id"] = user.Id
		if err := session.Save(r, w); err != nil {
			http.Error(w, "Error saving session", http.StatusInternalServerError)
			return
		}

		// Set HX-Location header and return 204 No Content status
		w.Header().Set("HX-Location", "/")
		w.WriteHeader(http.StatusNoContent)
	}
}

// Returns/Loads the "home" template.
func HomePage(db *sql.DB, tmpl *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, _ := CheckLoggedIn(w, r, store, db)
		if err := tmpl.ExecuteTemplate(w, "home.html", user); err != nil {
			log.Printf("Error executing template: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

// Checks if a user is already logged in and returns the user info and the id. If no session is available it redirects to the login page.
func CheckLoggedIn(w http.ResponseWriter, r *http.Request, store *sessions.CookieStore, db *sql.DB) (models.User, string) {
	session, err := store.Get(r, "logged-in-user")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return models.User{}, ""
	}

	// Check if the user_id is present in the session
	userId, ok := session.Values["user_id"]
	if !ok {
		log.Println("User ID not found in session, redirecting to /login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return models.User{}, ""
	}

	// Fetch user details from the database
	user, err := repository.GetUserById(db, userId.(string))
	if err != nil {
		if err == sql.ErrNoRows {
			// No user found, possibly handle by clearing the session or redirecting to login
			session.Options.MaxAge = -1 // Clear the session
			session.Save(r, w)
			log.Println("No user found, clearing session and redirecting to /login")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return models.User{}, ""
		}
		log.Printf("Error fetching user by ID: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return models.User{}, ""
	}

	return user, userId.(string)
}