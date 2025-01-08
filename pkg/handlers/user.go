package handlers

import (
	"database/sql"
	"html/template"
	"net/http"
)

// Returns/Loads the "register" template.
func RegisterPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl.ExecuteTemplate(w, "register", nil)
	}
}