package webcommon

import (
	"context"
	"embed"
	"html/template"
	"log"

	"lds.li/web"
)

//go:embed templates/*
var templates embed.FS

// LayoutData holds the data passed to templates
type LayoutData struct {
	Title          string
	UserLoggedIn   bool
	Username       string
	UserFullName   string
	UserEmail      string
	SuccessMessage string
	// Add more fields as needed for different pages
}

var Templates *template.Template

var FuncMap = template.FuncMap{
	"default": func(value, defaultValue interface{}) interface{} {
		if value == nil || value == "" {
			return defaultValue
		}
		return value
	},
}

// init parses all templates on package initialization
func init() {
	var err error

	Templates, err = template.New("").Funcs(web.TemplateFuncs(context.Background(), FuncMap)).ParseFS(templates, "templates/*.tmpl.html")
	if err != nil {
		log.Fatal("Failed to parse templates:", err)
	}
}
