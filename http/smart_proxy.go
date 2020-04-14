/*
Copyright (c) 2020, Arm Limited and affiliates.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
)

type SmartProxy struct {
	httpHandler http.Handler
	wsHandler   http.Handler
}

func SmartHTTPProxy(forwardingAddress func(string) string, caList *x509.CertPool, clientCert *tls.Certificate) *SmartProxy {
	proxyURL := &url.URL{
		Scheme: "https",
		Host:   forwardingAddress(""),
	}
	proxy := httputil.NewSingleHostReverseProxy(proxyURL)
	proxy.Transport = EdgeTransport(caList, clientCert)
	proxy.FlushInterval = -1
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		if director != nil {
			director(req)
		}

		req.Host = forwardingAddress(req.Host)
		req.URL.Host = req.Host
	}

	dialer := &websocket.Dialer{
		TLSClientConfig: &tls.Config{
			RootCAs: caList,
			GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return clientCert, nil
			},
		},
	}

	wsURL := *proxyURL
	wsURL.Scheme = "wss"
	wsHandler := &WebsocketProxyHandler{Dialer: dialer, ProxyURL: &wsURL, Upgrader: websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024}, forwardingAddress: forwardingAddress}

	return &SmartProxy{
		httpHandler: proxy,
		wsHandler:   wsHandler,
	}
}

func (smartProxy *SmartProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isWebsocketRequest(r) {
		smartProxy.wsHandler.ServeHTTP(w, r)
	} else {
		smartProxy.httpHandler.ServeHTTP(w, r)
	}
}

func isWebsocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" && strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

type WebsocketProxyHandler struct {
	Dialer            *websocket.Dialer
	ProxyURL          *url.URL
	Upgrader          websocket.Upgrader
	forwardingAddress func(string) string
}

func (websocketProxyHandler *WebsocketProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Upgrading connection for request %s %s\n", r.Method, r.URL.RequestURI())

	conn, err := websocketProxyHandler.Upgrader.Upgrade(w, r, nil)

	if err != nil {
		fmt.Printf("Unable to upgrade connection: %v\n", err.Error())

		return
	}

	fmt.Printf("Upgraded connection for request %s %s %s\n", r.Host, r.Method, r.URL.RequestURI())

	websocketProxyHandler.ProxyURL.Host = websocketProxyHandler.forwardingAddress(r.Host)

	header := http.Header{}
	header.Set("Host", websocketProxyHandler.ProxyURL.Host)

	fmt.Printf("Proxying websocket connection from %s to remote endpoint %s\n", r.URL.RequestURI(), websocketProxyHandler.ProxyURL.ResolveReference(r.URL).String())

	connBackend, _, err := websocketProxyHandler.Dialer.Dial(websocketProxyHandler.ProxyURL.ResolveReference(r.URL).String(), header)

	if err != nil {
		fmt.Printf("Unable to proxy connection to %s: %v\n", websocketProxyHandler.ProxyURL.ResolveReference(r.URL).String(), err)

		conn.Close()

		return
	}

	fmt.Printf("Proxied websocket connection from %s to remote endpoint %s\n", r.URL.RequestURI(), websocketProxyHandler.ProxyURL.ResolveReference(r.URL).String())

	errors := make(chan error, 2)
	cp := func(dest io.Writer, src io.Reader) {
		_, err := io.Copy(dest, src)
		errors <- err
	}

	go cp(connBackend.UnderlyingConn(), conn.UnderlyingConn())
	go cp(conn.UnderlyingConn(), connBackend.UnderlyingConn())

	go func() {
		err := <-errors
		fmt.Printf("Closing proxied connection: %v\n", err)

		conn.Close()
		connBackend.Close()
	}()
}
