package auth

import (
	"context"
	"embed"
	"fmt"
	"html/template"

	"lds.li/passidp/internal/webcommon"
	"lds.li/web"
	"lds.li/web/templateutil"
)

//go:embed templates/*
var templatesFS embed.FS

var templates *template.Template

func init() {
	t, err := template.New("").Funcs(web.TemplateFuncs(context.Background(), webcommon.FuncMap)).ParseFS(templatesFS, "templates/*.tmpl.html")
	if err != nil {
		panic(fmt.Sprintf("failed to parse templates: %v", err))
	}
	if err := templateutil.Merge(t, webcommon.Templates); err != nil {
		panic(fmt.Sprintf("failed to merge templates: %v", err))
	}
	templates = t
}

type loginData struct {
	webcommon.LayoutData
	FlowID            string
	WebauthnChallenge string
}
