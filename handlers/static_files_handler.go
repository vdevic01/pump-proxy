package handlers

import "net/http"

type StaticFilesHandler struct {
	BaseHandler
	staticDir string
}

func NewStaticFilesHandler(prefix string, staticDir string) *StaticFilesHandler {
	return &StaticFilesHandler{
		BaseHandler: BaseHandler{prefix: prefix},
		staticDir:   staticDir,
	}
}

func (h *StaticFilesHandler) RegisterEndpoints() {
	http.Handle(h.prefix+"/", http.StripPrefix(h.prefix, http.FileServer(http.Dir(h.staticDir))))
}
