package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed dist
var assets embed.FS

// ServeChallengeAsset serves only the separate public verification bundle.
// Missing assets never fall back to the administration application's HTML.
func ServeChallengeAsset(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "method not allowed", 405)
		return false
	}
	name := strings.TrimPrefix(r.URL.Path, "/.waf/challenge/assets/")
	if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return false
	}
	root, err := fs.Sub(assets, "dist/challenge")
	if err != nil {
		http.NotFound(w, r)
		return false
	}
	info, err := fs.Stat(root, name)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return false
	}
	w.Header().Set("Cache-Control", "no-cache")
	copy := r.Clone(r.Context())
	copy.URL.Path = "/" + name
	http.FileServer(http.FS(root)).ServeHTTP(w, copy)
	return true
}

func Handler() http.Handler {
	root, _ := fs.Sub(assets, "dist")
	files := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			http.Error(w, "method not allowed", 405)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "." {
			name = "index.html"
		}
		if _, err := fs.Stat(root, name); err != nil {
			if strings.Contains(name, ".") {
				http.NotFound(w, r)
				return
			}
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		w.Header().Set("Cache-Control", "no-cache")
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}
