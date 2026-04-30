package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	htmltemplate "html/template"
	"net/http"
	"strings"
	"time"

	"github.com/P3X-118/sgc-pds-admin/internal/audit"
	"github.com/P3X-118/sgc-pds-admin/internal/auth"
	"github.com/P3X-118/sgc-pds-admin/internal/config"
	"github.com/P3X-118/sgc-pds-admin/internal/goat"
	"github.com/go-chi/chi/v5"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

type Templates map[string]*htmltemplate.Template

type Server struct {
	cfg       *config.Config
	tpl       Templates
	sessions  *auth.Manager
	audit     *audit.Logger
	providers []string
}

func New(cfg *config.Config, tpl Templates, sm *auth.Manager, al *audit.Logger, providers []string) *Server {
	return &Server{cfg: cfg, tpl: tpl, sessions: sm, audit: al, providers: providers}
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	r.Get("/login", s.login)
	r.Get("/auth/{provider}", s.authStart)
	r.Get("/auth/{provider}/callback", s.authCallback)
	r.Post("/logout", s.logout)

	r.Group(func(r chi.Router) {
		r.Use(s.sessions.Middleware)
		r.Get("/", s.home)
		r.Get("/instances/{instance}/accounts", s.accountList)
		r.Get("/instances/{instance}/accounts/new", s.accountNewForm)
		r.Post("/instances/{instance}/accounts", s.accountCreate)
		r.Post("/instances/{instance}/accounts/{user}/takedown", s.accountTakedown)
	})

	return r
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	t, ok := s.tpl[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", map[string]any{"Providers": s.providers})
}

func (s *Server) authStart(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	q := r.URL.Query()
	q.Set("provider", provider)
	r.URL.RawQuery = q.Encode()
	gothic.BeginAuthHandler(w, r)
}

func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	q := r.URL.Query()
	q.Set("provider", provider)
	r.URL.RawQuery = q.Encode()

	gu, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, "auth failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	subject := fmt.Sprintf("%s|%s", provider, gu.UserID)
	decision := auth.Authorize(s.cfg.Allowlist, subject, gu.Email)
	if !decision.Allowed {
		s.audit.Log(audit.Entry{
			Subject: subject, Email: gu.Email, Provider: provider,
			Action: "login.denied", Result: "denied",
			Args: map[string]string{"name": fullName(gu)},
		})
		http.Error(w, "not authorized", http.StatusForbidden)
		return
	}

	if err := s.sessions.Save(w, r, auth.SessionUser{
		Subject:  subject,
		Email:    gu.Email,
		Name:     fullName(gu),
		Provider: provider,
		Roles:    decision.Roles,
		IssuedAt: time.Now().UTC(),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit.Log(audit.Entry{
		Subject: subject, Email: gu.Email, Provider: provider,
		Action: "login", Result: "ok",
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.sessions.Get(r); ok {
		s.audit.Log(audit.Entry{Subject: u.Subject, Email: u.Email, Provider: u.Provider, Action: "logout", Result: "ok"})
	}
	_ = s.sessions.Clear(w, r)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	s.render(w, "home.html", map[string]any{
		"User":      u,
		"Instances": s.cfg.Instances,
	})
}

func (s *Server) accountList(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	accounts, err := cli.AccountList(r.Context())
	result := "ok"
	errMsg := ""
	if err != nil {
		result = "error"
		errMsg = err.Error()
	}
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: "account.list", Result: result, Error: errMsg,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.render(w, "accounts.html", map[string]any{
		"User":     u,
		"Instance": inst,
		"Accounts": accounts,
	})
}

func (s *Server) accountNewForm(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, "account_new.html", map[string]any{"User": u, "Instance": inst})
}

func (s *Server) accountCreate(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if !auth.HasRole(u.Roles, "super-admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	handle := r.FormValue("handle")
	email := r.FormValue("email")
	password := r.FormValue("password")
	if password == "" {
		password = randomPassword()
	}
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out, err := cli.AccountCreate(r.Context(), goat.CreateAccountInput{
		Handle: handle, Email: email, Password: password,
	})
	result := "ok"
	errMsg := ""
	if err != nil {
		result = "error"
		errMsg = err.Error()
	}
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: "account.create", Result: result, Error: errMsg,
		Args: map[string]string{"handle": handle, "email": email},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.render(w, "account_created.html", map[string]any{
		"User":     u,
		"Instance": inst,
		"Handle":   handle,
		"Email":    email,
		"Password": password,
		"Output":   out,
	})
}

func (s *Server) accountTakedown(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if !auth.HasRole(u.Roles, "super-admin") && !auth.HasRole(u.Roles, "instance-admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	user := chi.URLParam(r, "user")
	reverse := r.URL.Query().Get("reverse") == "1"
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = cli.AccountTakedown(r.Context(), user, reverse)
	action := "account.takedown"
	if reverse {
		action = "account.takedown.reverse"
	}
	result := "ok"
	errMsg := ""
	if err != nil {
		result = "error"
		errMsg = err.Error()
	}
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: action, Result: result, Error: errMsg,
		Args: map[string]string{"user": user},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/instances/"+instName+"/accounts", http.StatusSeeOther)
}

func fullName(gu goth.User) string {
	if gu.Name != "" {
		return gu.Name
	}
	return strings.TrimSpace(gu.FirstName + " " + gu.LastName)
}

func randomPassword() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
