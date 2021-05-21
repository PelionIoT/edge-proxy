package server

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/gorilla/websocket"
)

/*
 * The purpose of this feature is  to allow tunneling of arbitrary TCP connections using the wstunnel protocol.
 * One use case for this is to allow tunneling of all Pelion edge traffic so through a restrictive corporate firewall.
 */

type WSTunnelConfig struct {
	ListenAddr string // Address of the listening port
	TunnelAddr string // Address of the remote wsTunnel server
}

type WSTunnelConnection struct {
	wc *websocket.Conn
	r  io.Reader // Current reader
}

func (wsc WSTunnelConnection) Read(b []byte) (int, error) {
	// read some
	if wsc.r == nil {
		for {
			messageType, r, err := wsc.wc.NextReader()
			if err != nil {
				return 0, err
			}
			if messageType == websocket.BinaryMessage {
				wsc.r = r
				break
			}
		}
	}

	n, err := wsc.r.Read(b)
	if err == io.EOF {
		wsc.r = nil
		return n, nil
	} else {
		return n, err
	}
}

func (wsc WSTunnelConnection) Write(b []byte) (int, error) {
	err := wsc.wc.WriteMessage(websocket.BinaryMessage, b)
	return len(b), err
}

func (wsc WSTunnelConnection) Close() error {
	return wsc.wc.Close()
}

func (wsc WSTunnelConnection) LocalAddr() net.Addr {
	return wsc.wc.LocalAddr()
}

func (wsc WSTunnelConnection) RemoteAddr() net.Addr {
	return wsc.wc.RemoteAddr()
}

func (wsc WSTunnelConnection) SetDeadline(t time.Time) error {
	err := wsc.wc.SetReadDeadline(t)
	if err != nil {
		return err
	}

	return wsc.wc.SetWriteDeadline(t)
}

func (wsc WSTunnelConnection) SetReadDeadline(t time.Time) error {
	return wsc.wc.SetReadDeadline(t)
}

func (wsc WSTunnelConnection) SetWriteDeadline(t time.Time) error {
	return wsc.wc.SetWriteDeadline(t)
}

// StartWSTunnel starts a server that accepts HTTP CONNECT method to proxy arbitrary TCP connections.
//
func StartWSTunnel(config *WSTunnelConfig) error {
	proxy := goproxy.NewProxyHttpServer()

	_, err := url.Parse(config.TunnelAddr)
	if err != nil {
		log.Printf("WebSocket Tunnel: failed to parse external proxy: %s\n", err.Error())
		return err
	}
	proxy.Tr = &http.Transport{
		// Configuration for non-CONNECT requests
		Proxy: func(req *http.Request) (*url.URL, error) {
			return nil, errors.New("This proxy can only handle CONNECT requests.")
		},
	}
	proxy.ConnectDial = func(network string, addr string) (net.Conn, error) {
		path, err := wsTunnelPathFromConnectAddr(addr)
		if err != nil {
			return nil, err
		}
		u := url.URL{Scheme: "ws", Host: config.TunnelAddr, Path: path}
		log.Printf("WebSocket Tunnel: Connecting to %v", u)

		// TODO: support next proxy
		conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err != nil {
			return nil, errors.New("Failed to open ws tunnel: " + err.Error())
		}

		wsc := &WSTunnelConnection{
			wc: conn,
			r:  nil,
		}

		return wsc, nil
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

func wsTunnelPathFromConnectAddr(addr string) (string, error) {
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		_, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return "", errors.New("Failed to parse port")
		}
	} else {
		return "", errors.New("Failed to parse address")
	}

	host := parts[0]
	port := parts[1]
	path := fmt.Sprintf("/wstunnel/tcp/%v/%v", host, port)
	return path, nil
}
