package server

import (
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/elazarl/goproxy"
)

/*
 * The purpose of this feature is  to allow tunneling of arbitrary TCP connections using the wstunnel protocol.
 * One use case for this is to allow tunneling of all Pelion edge traffic so through a restrictive corporate firewall.
 */

type WSTunnelConfig struct {
	ListenAddr string // Address of the listening port
	TunnelAddr string // Address of the remote wsTunnel server
}

// StartWSTunnel starts a server that accepts HTTP CONNECT method to proxy arbitrary TCP connections.
//
func StartWSTunnel(config *WSTunnelConfig) error {
	proxy := goproxy.NewProxyHttpServer()

	_, err := url.Parse(config.TunnelAddr)
	if err != nil {
		log.Printf("HTTP(S) Tunnel: failed to parse external proxy: %s\n", err.Error())
		return err
	}
	proxy.Tr = &http.Transport{
		// Configuration for non-CONNECT requests
		Proxy: func(req *http.Request) (*url.URL, error) {
			return nil, errors.New("This proxy can only handle CONNECT requests.")
		},
	}
	proxy.ConnectDial = func(network string, addr string) (net.Conn, error) {
		// TODO: handle connecting to a new address
		// network: "tcp", maybe "tcp6"
		// addr: a URL, something like "https://www.example.com"
		return nil, errors.New("Not implemented.")
	}

	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		log.Printf("WebSocket Tunnel: got CONNECT request %s\n", host)
		return nil, host
	})

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// Leave the request untouched.  Log a message for debugging purposes.
			log.Printf("HTTP Tunnel: got request %s\n", r.URL)
			return r, nil
		})

	log.Printf("WS Tunnel: starting on %s\n", config.ListenAddr)
	err = http.ListenAndServe(config.ListenAddr, proxy)
	if err != nil {
		log.Printf("WS Tunnel encountered an error while starting: %s\n", err.Error())
		return err
	}

	// Should not get here
	return nil
}
