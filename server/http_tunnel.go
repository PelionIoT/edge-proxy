package server

import (
	"crypto/tls"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/ext/auth"
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
func StartHTTPTunnel(addr, externalProxy string) error {
	return StartHTTPSTunnel(addr, externalProxy, "", "", "", "")
}

func StartHTTPSTunnel(addr, externalProxy, certFile, keyFile, username, password string) error {
	proxy := goproxy.NewProxyHttpServer()

	if externalProxy != "" {
		u, err := url.Parse(externalProxy)
		if err != nil {
			log.Printf("HTTP(S) Tunnel: failed to parse external proxy: %s\n", err.Error())
			return err
		}
		proxy.Tr = &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return u, nil
			},
			TLSClientConfig: &tls.Config{
				ServerName: u.Hostname(),
			},
		}
		proxy.ConnectDial = proxy.NewConnectDialToProxyWithHandler(externalProxy, func(req *http.Request) {
			if u.User != nil {
				credentials := base64.StdEncoding.EncodeToString([]byte(u.User.String()))
				req.Header.Add("Proxy-Authorization", "Basic "+credentials)
			}
		})
	}

	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		log.Printf("HTTP Tunnel: got CONNECT request %s\n", host)
		return nil, host
	})

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// Leave the request untouched.  Log a message for debugging purposes.
			log.Printf("HTTP Tunnel: got request %s\n", r.URL)
			return r, nil
		})

	if username != "" || password != "" {
		auth.ProxyBasic(proxy, "tunnel", func(user, passwd string) bool {
			authorized := (user == username && passwd == password)
			log.Printf("HTTP Tunnel: authorized=%t\n", authorized)
			return authorized
		})
	}

	if certFile == "" || keyFile == "" {
		log.Printf("HTTP Tunnel: starting a plain HTTP tunnel on %s\n", addr)
		err := http.ListenAndServe(addr, proxy)
		if err != nil {
			log.Printf("HTTP Tunnel encountered an error while starting: %s\n", err.Error())
			return err
		}
	} else {
		log.Printf("HTTP Tunnel: starting HTTP tunnel over TLS on %s\n", addr)
		err := http.ListenAndServeTLS(addr, certFile, keyFile, proxy)
		if err != nil {
			log.Printf("HTTP Tunnel over TLS encountered an error while starting: %s\n", err.Error())
			return err
		}
	}

	// Should not get here
	return nil
}
