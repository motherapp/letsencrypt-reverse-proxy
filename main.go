package main

import (
	"crypto/tls"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const cache autocert.DirCache = "/tmp" // path to cert store folder with right priviliges
var webDomain = func() string {
	port, ok := os.LookupEnv("DOMAINS")
	if !ok {
		return "example.com,www.example.com"
	}
	return port
}()

var proxyToUrlsCommaSeparated = func() string {
	port, ok := os.LookupEnv("PROXY_TO_URLS")
	if !ok {
		return "serverIWantToProxyTo.example.com:443,other2.example.com:443"
	}
	return port
}()

var port = func() string {
	port, ok := os.LookupEnv("PORT")
	if !ok {
		return "443"
	}
	return port
}()

var contactEmail = func() string {
	contactEmail := os.Getenv("DOMAIN_CONTACT_EMAIL")
	if contactEmail == "" {
		contactEmail = "info@example.com"
	}
	return contactEmail
}()

func main() {
	logger := log.New(os.Stdout, "http: ", log.LstdFlags)
	logger.SetFlags(log.LstdFlags | log.Lshortfile)
	logger.Println("started proxy")

	domains := strings.Split(webDomain, ",")
	manager, tlsConfig := getTLS(domains...)

	proxies := []*httputil.ReverseProxy{}
	proxyToUrls := strings.Split(proxyToUrlsCommaSeparated, ",")

	if len(proxyToUrls) == 0 {
		logger.Printf("no proxyToUrl set")
		return
	}

	if len(domains) == 0 {
		logger.Printf("no domains set")
		return
	}

	if len(domains) != len(proxyToUrls) {
		logger.Printf("domains and proxies are uneven")
		return
	}

	for _, proxyToUrl := range proxyToUrls {
		proxyUrl, err := url.Parse(proxyToUrl)
		if err != nil {
			logger.Printf("bad address %+v, %+v", err, proxyToUrlsCommaSeparated)
			return
		}
	    proxy := httputil.NewSingleHostReverseProxy(proxyUrl)
	    director := proxy.Director
	    proxy.Director = func(r *http.Request) {
	        director(r)
	        r.Host = proxyUrl.Host
	    }		
		proxies = append(proxies, proxy)
	}

	handler := func(resp http.ResponseWriter, req *http.Request) {
		trimmedAddr := strings.Trim(req.Host, ":"+port)
		logger.Printf("request url %+v, %v", trimmedAddr, req.URL.Path)
		for index, url := range domains {
			if trimmedAddr != url {
				continue
			}
			proxies[index].ServeHTTP(resp, req)
			return
		}
		logger.Printf("failed finding domain %v", trimmedAddr)
		return
	}

	httpServer := http.Server{
		Addr:         ":" + port,
		Handler:      http.HandlerFunc(handler),
		TLSConfig:    tlsConfig,
		ErrorLog:     logger,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	go func() {
		serveError := http.ListenAndServe(":80", manager.HTTPHandler(redirecter{}))
		if serveError != nil {
			logger.Printf("got serve error when setting up port 80 listner %v", serveError)
		}
	}()

	logger.Println("run manager listner tls")
	err := httpServer.ListenAndServeTLS("", "")
	if err != nil {
		logger.Printf("error: %+v", err)
		return
	}
}

func getTLS(hosts ...string) (*autocert.Manager, *tls.Config) {
	manager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      cache,
		HostPolicy: autocert.HostWhitelist(hosts...),
		Email:      contactEmail,
	}
	tlsConfig := &tls.Config{
		GetCertificate: manager.GetCertificate,
	}
	return &manager, tlsConfig
}

type redirecter struct{}

func (r redirecter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// remove/add not default ports from req.Host
	target := "https://" + req.Host + req.URL.Path
	if len(req.URL.RawQuery) > 0 {
		target += "?" + req.URL.RawQuery
	}

	http.Redirect(w, req, target,
		// see @andreiavrammsd comment: often 307 > 301
		http.StatusTemporaryRedirect)
}
