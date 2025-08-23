package main

import (
	"PumpProxy/config"
	"PumpProxy/handlers"
	"PumpProxy/kube"
	saservice "PumpProxy/services/sa-service"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/davecgh/go-spew/spew"
)

type WebServer struct {
	proxyConfig *config.ProxyConfig
	proxy       *httputil.ReverseProxy
	kubeClient  *kube.KubeClient
	saService   *saservice.SAService
}

func NewWebServer(proxyConfig *config.ProxyConfig) *WebServer {
	proxy := httputil.NewSingleHostReverseProxy(proxyConfig.TargetURL)
	kubeClient := kube.NewKubeClient(proxyConfig)
	saService := saservice.NewSAService(proxyConfig, kubeClient)

	return &WebServer{
		proxyConfig: proxyConfig,
		proxy:       proxy,
		kubeClient:  kubeClient,
		saService:   saService,
	}
}

func (ws *WebServer) ServeHTTP() {
	staticFileHandler := handlers.NewStaticFilesHandler("/pumpproxy/static", "./static")
	proxyHandler := handlers.NewProxyHandler("", ws.proxyConfig)
	authPageHandler := handlers.NewAuthPageHandler("/pumpproxy", ws.proxyConfig)

	var internalHandler handlers.HttpHandler
	if ws.proxyConfig.Auth == config.AuthOIDC {
		internalHandler = handlers.NewOIDCHandler("/pumpproxy", ws.proxyConfig, ws.saService)
	} else {
		internalHandler = handlers.NewSAMLHandler("/pumpproxy", ws.proxyConfig, ws.saService)
	}

	handlers := []handlers.HttpHandler{
		staticFileHandler,
		proxyHandler,
		authPageHandler,
		internalHandler,
	}

	for _, h := range handlers {
		h.RegisterEndpoints()
	}

	addr := ws.proxyConfig.Host + ":" + fmt.Sprintf("%d", ws.proxyConfig.Port)

	asciiArt := `
	 ____                        
	|  _ \ _   _ _ __ ___  _ __  
	| |_) | | | | '_ ` + "`" + ` _ \| '_ \ 
	|  __/| |_| | | | | | | |_) |
	|_|    \__,_|_| |_| |_| .__/ 
	 ____                  |_|    
	|  _ \ _ __ _____  ___   _   
	| |_) | '__/ _ \ \/ / | | |  
	|  __/| | | (_) >  <| |_| |  
	|_|   |_|  \___/_/\_\\__, |  
                             |___/
	`

	fmt.Println(asciiArt)
	fmt.Printf("PumpProxy server started on http://%s\n", addr)
	fmt.Println("=================================================")
	http.ListenAndServe(addr, nil)
}

func main() {
	var configFilePath = flag.String("config-file", "default_config.toml", "Path to config file")
	flag.Parse()
	configViper := &config.ProxyConfigDto{}
	err := config.Load(*configFilePath, configViper)
	if err != nil {
		panic(fmt.Errorf("error parsing configuration: %w", err))
	}

	proxyConfig, err := config.NewProxyConfig(configViper)
	if err != nil {
		panic(fmt.Errorf("error parsing configuration: %w", err))
	}
	if proxyConfig.RunInDebug {
		spew.Dump(proxyConfig)
	}

	ws := NewWebServer(proxyConfig)
	ws.ServeHTTP()
}
