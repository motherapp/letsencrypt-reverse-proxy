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
	"fmt"
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
	domains := strings.Split(webDomain, ",")
	manager, tlsConfig := getTLS(domains...)

	proxies := []*httputil.ReverseProxy{}
	proxyToUrls := strings.Split(proxyToUrlsCommaSeparated, ",")

	if len(proxyToUrls) == 0 {
		log.Printf("no proxyToUrl set")
		return
	}

	if len(domains) == 0 {
		log.Printf("no domains set")
		return
	}

	if len(domains) != len(proxyToUrls) {
		log.Printf("domains and proxies are uneven")
		return
	}

	for _, proxyToUrl := range proxyToUrls {
		proxyUrl, err := url.Parse(proxyToUrl)
		if err != nil {
			log.Printf("bad address %+v, %+v", err, proxyToUrlsCommaSeparated)
			return
		}
		proxies = append(proxies, httputil.NewSingleHostReverseProxy(proxyUrl))
	}

	handler := func(resp http.ResponseWriter, req *http.Request) {
		trimmedAddr := strings.Trim(req.Host, ":"+port)
		log.Printf("request url %+v, %v", trimmedAddr, webDomain)
		for index, url := range domains {
			if trimmedAddr != url {
				continue
			}
			proxies[index].ServeHTTP(resp, req)
			return
		}
		log.Printf("failed finding domain %v", trimmedAddr)
		return
	}

	go func() {
		serveError := http.ListenAndServe(":80", manager.HTTPHandler(redirecter{}))
		if serveError != nil {
			fmt.Errorf("got serve error when setting up port 80 listner %v", serveError)
		}
	}()

	httpServer := http.Server{
		Addr:      ":" + port,
		Handler:   http.HandlerFunc(handler),
		TLSConfig: tlsConfig,
	}
	err := httpServer.ListenAndServeTLS("", "")
	if err != nil {
		log.Printf(" %+v", err)
		return
	}
}

func getTLS(hosts ...string) (autocert.Manager, *tls.Config) {
	manager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      cache,
		HostPolicy: autocert.HostWhitelist(hosts...),
		Email:      contactEmail,
	}
	tlsConfig := &tls.Config{GetCertificate: manager.GetCertificate}
	return manager, tlsConfig
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
