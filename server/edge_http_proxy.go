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

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	fog_http "github.com/PelionIoT/edge-proxy/http"
)

func RunEdgeHTTPProxyServer(ctx context.Context, listenAddr string, forwardingAddress func(string) string, caList *x509.CertPool, clientCert *tls.Certificate, proxyForEdge func(* http.Request) (*url.URL, error)) {
	handler := fog_http.EdgeHTTPProxy(forwardingAddress, caList, clientCert, proxyForEdge)
	listener, err := net.Listen("tcp", listenAddr)

	if err != nil {
		fmt.Printf("Failed to start listener: %s\n", err.Error())

		return
	}

	defer listener.Close()

	httpServer := &http.Server{
		Handler:      handler,
		WriteTimeout: 45 * time.Second,
		ReadTimeout:  300 * time.Second,
	}

	go func() {
		<-ctx.Done()

		if err := httpServer.Shutdown(context.Background()); err != nil {
			fmt.Printf("HTTP edge proxy server could not be shut down with error: %s\n", err.Error())
		}
	}()

	err = httpServer.Serve(listener)

	fmt.Printf("HTTP edge proxy server shut down with error: %s\n", err.Error())
}

func RunEdgeTLSProxyServer(ctx context.Context, listenAddr string, cloudURL *url.URL, caList *x509.CertPool, clientCert *tls.Certificate) {
	host := host(cloudURL)
	listener, err := net.Listen("tcp", listenAddr)

	if err != nil {
		fmt.Printf("Failed to start listener: %s\n", err.Error())

		return
	}

	defer listener.Close()

	tlsConfig := &tls.Config{
		RootCAs: caList,
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		},
	}

	var i uint64

	for {
		conn, err := listener.Accept()

		if err != nil {
			fmt.Printf("Proxy listener accept error: %s\n", err.Error())

			return
		}

		i++

		go func(i uint64, conn net.Conn) {
			defer conn.Close()

			fmt.Printf("New connection %d (localAddr=%s,remoteAddr=%s). Proxy to %s\n", i, conn.LocalAddr().String(), conn.RemoteAddr().String(), host)

			proxyConn, err := tls.Dial("tcp", host, tlsConfig)

			if err != nil {
				fmt.Printf("Unable to dial proxy connection for %d: %v\n", i, err)

				return
			}

			defer proxyConn.Close()

			childCtx, cancel := context.WithCancel(ctx)

			go func() {
				_, err := io.Copy(proxyConn, conn)
				fmt.Printf("Pipe (local->cloud) for connection %d broken with error: %v\n", i, err)
				cancel()
			}()

			go func() {
				_, err := io.Copy(conn, proxyConn)
				fmt.Printf("Pipe (local<-cloud) for connection %d broken with error: %v\n", i, err)
				cancel()
			}()

			// If either of the previous goroutines cancel the context, all will be cleaned up when this function returns since it closes
			// all the connections
			<-childCtx.Done()
			fmt.Printf("Shut down proxy for connection %d\n", i)
		}(i, conn)
	}
}

func host(u *url.URL) string {
	port := "443"

	if u.Port() != "" {
		port = u.Port()
	}

	return fmt.Sprintf("%s:%s", u.Hostname(), port)
}
