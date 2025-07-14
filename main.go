package main

import (
	"PumpProxy/config"
	"PumpProxy/handlers"
	"PumpProxy/kube"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
)

type WebServer struct {
	proxyConfig *config.ProxyConfig
	proxy       httputil.ReverseProxy
	kubeClient  kube.KubeClient
}

func NewWebServer(proxyConfig *config.ProxyConfig) *WebServer {
	proxy := httputil.NewSingleHostReverseProxy(proxyConfig.TargetURL)
	kubeClient := kube.NewKubeClient()

	return &WebServer{
		proxyConfig: proxyConfig,
		proxy:       *proxy,
		kubeClient:  *kubeClient,
	}
}

func (ws *WebServer) ServeHTTP() {
	staticFileHandler := handlers.NewStaticFilesHandler("/pumpproxy/static", "./static")
	staticFileHandler.RegisterEndpoints()

	proxyHandler := handlers.NewProxyHandler("", ws.proxyConfig)
	proxyHandler.RegisterEndpoints()

	internalHandler := handlers.NewInternalHandler("/pumpproxy", ws.proxyConfig, &ws.kubeClient)
	internalHandler.RegisterEndpoints()

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

	configViper := config.NewProxyConfigViper()
	err := config.Load(*configFilePath, configViper)
	if err != nil {
		panic(fmt.Errorf("error parsing configuration: %w", err))
	}

	proxyConfig, err := config.NewProxyConfig(configViper)
	if err != nil {
		panic(fmt.Errorf("error parsing configuration: %w", err))
	}

	ws := NewWebServer(proxyConfig)
	ws.ServeHTTP()
}
