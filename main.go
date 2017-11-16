package main

import (
	"crypto/tls"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

const cache autocert.DirCache = "/tmp" // path to cert store folder with right priviliges
var webDomain = func() string {
	port, ok := os.LookupEnv("DOMAIN")
	if !ok {
		return "example.com"
	}
	return port
}()

var webAddr = func() string {
	port, ok := os.LookupEnv("PROXY_TO_URL")
	if !ok {
		return "other.example.com:443"
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
		contactEmail = "info@einride.eu"
	}
	return contactEmail
}()

func main() {
	tlsConfig := GetTLS(webDomain)

	proxyUrl, err := url.Parse(webAddr)
	if err != nil {
		log.Printf("bad address %+v, %+v", err, webAddr)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(proxyUrl)

	handler := func(resp http.ResponseWriter, req *http.Request) {
		proxy.ServeHTTP(resp, req)
		return
	}

	httpServer := http.Server{
		Addr:      ":" + port,
		Handler:   http.HandlerFunc(handler),
		TLSConfig: tlsConfig,
	}

	err = httpServer.ListenAndServeTLS("", "")
	if err != nil {
		log.Printf(" %+v", err)
		return
	}
}

func GetTLS(hosts ...string) *tls.Config {
	manager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      cache,
		HostPolicy: autocert.HostWhitelist(hosts...),
		Email:      contactEmail,
	}
	tlsConfig := &tls.Config{GetCertificate: manager.GetCertificate}
	return tlsConfig
}
