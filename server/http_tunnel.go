package server

import (
	"log"
	"net/http"
	"net/url"

	"github.com/elazarl/goproxy"
)

/*
 * The purpose of this feature is  to allow tunneling of arbitrary HTTP(S) connections.
 * One use case for this is to allow tunneling of all Pelion edge traffic over an authenticated
 * proxy, so that we can function behind restrictive firewalls that only allow HTTP(S)
 * traffic to pass through them.  As opposed to adding tuneling code to each service, it
 * would be easier to have edge-proxy handle tunneling configuration in one place.
 */

// StartHTTPTunnel starts a server that accepts to the HTTP CONNECT method to proxy arbitrary TCP connections.
// It can be used to tunnel HTTPS connections.
func StartHTTPTunnel(addr, externalProxy string) {
	StartHTTPSTunnel(addr, externalProxy, "", "")
}

func StartHTTPSTunnel(addr, externalProxy, certFile, KeyFile string) {
	proxy := goproxy.NewProxyHttpServer()

	if externalProxy != "" {
		proxy.Tr = &http.Transport{Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(externalProxy)
		}}
		proxy.ConnectDial = proxy.NewConnectDialToProxy(externalProxy)
	}
	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// Leave the request untouched.  Log a message for debugging purposes.
			log.Printf("HTTP Tunnel: got request %s\n", r.URL)
			return r, nil
		})

	if certFile == "" || KeyFile == "" {
		log.Printf("HTTP Tunnel: starting a plain HTTP tunnel on %s\n", addr)
		err := http.ListenAndServe(addr, proxy)
		if err != nil {
			log.Printf("HTTP Tunnel encountered an error while starting: %s\n", err.Error())
		}
	} else {
		log.Printf("HTTP Tunnel: starting HTTP tunnel over TLS on %s\n", addr)
		err := http.ListenAndServeTLS(addr, certFile, KeyFile, proxy)
		if err != nil {
			log.Printf("HTTP Tunnel over TLS encountered an error while starting: %s\n", err.Error())
		}
	}
}
