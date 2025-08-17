package handlers

import (
	"PumpProxy/logging"
	saservice "PumpProxy/services/sa-service"
	"errors"
	"fmt"
	"net/http"
)

type SAHandler struct {
	BaseHandler
	saService *saservice.SAService
}

func NewSAHandler(prefix string, saService *saservice.SAService) *SAHandler {
	return &SAHandler{
		BaseHandler: BaseHandler{prefix: prefix},
		saService:   saService,
	}
}

func (h *SAHandler) handleSAToken(w http.ResponseWriter, r *http.Request, groups []string, email string) error {
	saToken, saName, err := h.saService.AcquireSAToken(groups, email)
	if err != nil {
		var forbiddenErr *saservice.SAServiceForbiddenError
		var internalErr *saservice.SAServiceInternalError

		switch {
		case errors.As(err, &forbiddenErr):
			http.Error(w, "You are not authorized to use Kubernetes Dashboard", http.StatusForbidden)
			logging.LogRequest(r.Method, r.URL.String(), http.StatusForbidden)
			logging.LogError(err)
		case errors.As(err, &internalErr):
			http.Error(w, "Authentication failed", http.StatusInternalServerError)
			logging.LogRequest(r.Method, r.URL.String(), http.StatusInternalServerError)
			logging.LogError(err)
		default:
			http.Error(w, "Authentication failed", http.StatusInternalServerError)
			logging.LogRequest(r.Method, r.URL.String(), http.StatusInternalServerError)
			logging.LogError(err)
		}
		return err
	}

	h.deleteCookies(w, r)

	saTokenCookie, err := h.saService.GenerateSATokenCookie(saToken)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusInternalServerError)
		logging.LogError(err)
		return err
	}
	http.SetCookie(w, saTokenCookie)

	http.Redirect(w, r, "/", http.StatusSeeOther)
	logging.LogInfo(fmt.Sprintf("User %s authenticated successfully with service account %s", email, saName))

	return nil
}
