package handlers

import (
	"net/http"
	"time"
)

type HttpHandler interface {
	RegisterEndpoints()
}

type BaseHandler struct {
	prefix string
}

func (h *BaseHandler) deleteCookies(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		http.SetCookie(w, &http.Cookie{
			Name:     cookie.Name,
			Value:    "",
			Path:     "/pumpproxy",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: cookie.HttpOnly,
			Secure:   cookie.Secure,
			SameSite: cookie.SameSite,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     cookie.Name,
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: cookie.HttpOnly,
			Secure:   cookie.Secure,
			SameSite: cookie.SameSite,
		})
	}
}
