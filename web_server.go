package main

import (
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/gorilla/mux"
)

const (
	tmplLanding     = "homepage.html"
	tmplAfterLogout = "after_logout.html"
)

var (
	ThemesPath = "/site/themes"
)

type WebServer struct {
	TemplatePaths []string
	// Frontend-related values for context
	ProviderURL string
	ClientName  string
	ThemeURL    string
	Frontend    map[string]string
}

func (s *WebServer) Start(addr string) error {

	// Start web server
	// Load templates
	filenames := []string{}
	for _, p := range s.TemplatePaths {
		tmpls, err := listTemplates(p)
		if err != nil {
			return err
		}
		filenames = append(filenames, tmpls...)
	}

	// Add functions to context
	funcs := map[string]interface{}{
		"resolve_url_ref": func(url, ref string) string {
			return common.MustParseURL(url).ResolveReference(common.MustParseURL(ref)).String()
		},
	}

	templates, err := template.New("").Funcs(funcs).ParseFiles(filenames...)
	if err != nil {
		return err
	}

	router := mux.NewRouter()

	data := struct {
		// Frontend-related values for context
		Frontend map[string]string
		// OIDC-related settings
		ProviderURL string
		ThemeURL    string
		ClientName  string
	}{
		Frontend:    s.Frontend,
		ProviderURL: s.ProviderURL,
		ThemeURL:    s.ThemeURL,
		ClientName:  s.ClientName,
	}
	router.HandleFunc(common.HomepagePath, siteHandler(templates.Lookup(tmplLanding), data)).Methods(http.MethodGet)
	router.HandleFunc(common.AfterLogoutPath, siteHandler(templates.Lookup(tmplAfterLogout), data)).Methods(http.MethodGet)

	// Themes
	router.
		PathPrefix(ThemesPath).
		Handler(
			http.StripPrefix(
				ThemesPath,
				http.FileServer(http.Dir("web/themes")),
			),
		)

	return http.ListenAndServe(addr, router)
}

// siteHandler returns an http.HandlerFunc that serves a given template
func siteHandler(tmpl *template.Template, data interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := common.RequestLogger(r, "web server")
		if err := tmpl.Execute(w, data); err != nil {
			logger.Errorf("Error executing template: %v", err)
		}
	}
}

func listTemplates(dir string) ([]string, error) {
	tmplPaths := []string{}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".html") {
			tmplPaths = append(tmplPaths, filepath.Join(dir, f.Name()))
		}
	}
	return tmplPaths, err
}
