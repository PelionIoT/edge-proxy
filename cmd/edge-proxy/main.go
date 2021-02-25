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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PelionIoT/edge-proxy/cmd"
	"github.com/PelionIoT/edge-proxy/server"
	fog_tls "github.com/PelionIoT/edge-proxy/tls"
	"github.com/PelionIoT/remotedialer"
	"github.com/gorilla/websocket"
)

const TunnelBackoffSeconds = 10
const ServerBackoffSeconds = 10

var tunnelURI string
var proxyURI string
var proxyAddr string
var externalHTTPProxyURI string
var ca string
var certStrategy string
var useL4Proxy bool
var certStrategyOptions cmd.OptionMap = cmd.OptionMap{}
var forwardingAddressesMap string
var httpTunnelAddr string

func initEdgeProxy(proxyURIParsed *url.URL) {
	var forwardingAddressesMapParsed map[string]string

	err := json.Unmarshal([]byte(forwardingAddressesMap), &forwardingAddressesMapParsed)
	if err != nil {
		fmt.Printf("forwarding-addresses invalid: %s\n", err.Error())
		os.Exit(1)
	}

	var caList *x509.CertPool

	if ca != "" {
		fmt.Printf("Loading CA from %s\n", ca)
		caList, err = loadCA(ca)
		if err != nil {
			fmt.Printf("Unable to load CA from %s: %s\n", ca, err.Error())
			os.Exit(1)
		}
	}

	certificate, renewals, err := fog_tls.MakeCertificate(certStrategy, fog_tls.CertStrategyConfig(certStrategyOptions))
	if err != nil {
		fmt.Printf("Unable to initialize client certificate: %s\n", err.Error())
		os.Exit(1)
	}

	go func() {
		for {
			fmt.Printf("Establishing edge-proxy reverse tunnel (tunnelURI=%s)\n", tunnelURI)
			remotedialer.ClientConnect(tunnelURI, http.Header{}, &websocket.Dialer{
				NetDial: func(network, address string) (net.Conn, error) {
					netDialer := &net.Dialer{}
					return netDialer.Dial("tcp", proxyAddr)
				},
			}, func(string, string) bool { return true }, func(ctx context.Context) error {
				fmt.Printf("edge-proxy reverse tunnel established\n")
				return nil
			})

			fmt.Printf("edge-proxy tunnel exited. Attempting to reestablish tunnel in %d seconds...\n", TunnelBackoffSeconds)
			time.Sleep(time.Second * TunnelBackoffSeconds)
		}
	}()

	go func(cert *tls.Certificate) {
		for {
			childCtx, cancelChildCtx := context.WithCancel(context.Background())

			go func() {
				c := <-renewals
				cert = c
				fmt.Print("edge-proxy received a renewal cert. Proxy server should be re-launched with the new cert...\n")
				cancelChildCtx()
			}()

			if useL4Proxy {
				fmt.Printf("Starting edge TLS proxy (proxyAddr=%s, proxyURI=%s)\n", proxyAddr, proxyURI)
				server.RunEdgeTLSProxyServer(childCtx, proxyAddr, proxyURIParsed, caList, cert)
				fmt.Printf("Edge TLS proxy server exited\n")
			} else {
				fmt.Printf("Starting edge HTTP proxy (proxyAddr=%s, proxyURI=%s)\n", proxyAddr, proxyURI)
				proxyForEdge := func(req *http.Request) (*url.URL, error) {

					if externalHTTPProxyURI != "" {
						var proxy *url.URL
						proxy, err := url.Parse(externalHTTPProxyURI)
						if err == nil {
							return proxy, nil
						}
					}

					return nil, nil
				}

				server.RunEdgeHTTPProxyServer(childCtx, proxyAddr, forwardingAddresses(proxyURIParsed, forwardingAddressesMapParsed), caList, cert, proxyForEdge)

				fmt.Printf("Edge HTTP proxy server exited\n")
			}

			fmt.Printf("edge-proxy proxy server shut down. Attemtping to re-launch proxy server in %d seconds...\n", ServerBackoffSeconds)

			<-time.After(time.Second * ServerBackoffSeconds)
		}
	}(certificate)
}

func initHttpProxy(httpTunnelAddr string) {
	server.StartHTTPTunnel(httpTunnelAddr)
}

func main() {
	flag.StringVar(&tunnelURI, "tunnel-uri", "ws://localhost:8181/connect", "Endpoint to connect to for reverse tunneling")
	flag.StringVar(&proxyURI, "proxy-uri", "", "Default server to which outgoing HTTP requests should be forwarded.  See forwarding-addresses option for overrides")
	flag.StringVar(&proxyAddr, "proxy-listen", "0.0.0.0:8080", "Listen address for HTTP proxy server")
	flag.StringVar(&externalHTTPProxyURI, "extern-http-proxy-uri", "", "optional external Http proxy for site. For an authenticated proxy, specify the username and password in the URI, as in https://user:pwd@proxy-server:proxy-port")
	flag.BoolVar(&useL4Proxy, "use-l4-proxy", false, "Use a layer 4 proxy instead of a layer 7 proxy")
	flag.StringVar(&ca, "ca", "", "Certificate authority for the cloud")
	flag.StringVar(&certStrategy, "cert-strategy", fog_tls.DefaultDriver(), fmt.Sprintf("Certificate strategy must be one of: %v", fog_tls.Drivers()))
	flag.Var(&certStrategyOptions, "cert-strategy-options", "Can be specified one or more times. Must be a key-value pair (<key>=<value>)")
	flag.StringVar(&forwardingAddressesMap, "forwarding-addresses", "{}", "Map of local address to forwarded address for outgoing HTTP requests. For each forwarding request received at proxy-listen, the destination URI in the request is rewritten based on this map, where the destination server is replaced with the value of the corresponding key.  If the destination server isn't found in this map, then the value of proxy-uri is used.  Must be a json string")
	flag.StringVar(&httpTunnelAddr, "http-tunnel-listen", "localhost:8888", "Listen address for HTTP (CONNECT) tunnel server")
	flag.Parse()

	var proxyURIParsed *url.URL
	if proxyURI == "" {
		fmt.Printf("proxy-uri was not provided, starting in CONNECT only mode\n")
	} else {
		p, err := url.Parse(proxyURI)
		if err != nil {
			fmt.Printf("proxy-uri invalid: %s\n", err.Error())
			os.Exit(1)
		}
		proxyURIParsed = p
	}

	if tunnelURI == "" {
		fmt.Printf("tunnel-uri must be provided\n")

		os.Exit(1)
	}

	if externalHTTPProxyURI != "" {
		_, err := url.Parse(externalHTTPProxyURI)
		if err != nil {
			fmt.Printf("extern-http-proxy-uri invalid: %s\n", err.Error())

			os.Exit(1)
		}
	}

	if proxyURIParsed != nil {
		initEdgeProxy(proxyURIParsed)
	}

	if httpTunnelAddr != "" {
		initHttpProxy(httpTunnelAddr)
	}

	blockforever := make(chan struct{})
	<-blockforever
}

func loadCA(caFile string) (*x509.CertPool, error) {
	ca, err := ioutil.ReadFile(caFile)

	if err != nil {
		return nil, err
	}

	caList := x509.NewCertPool()

	if !caList.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("Could not append CA to chain")
	}

	return caList, nil
}

func forwardingAddresses(defaultForwardingURL *url.URL, addrMap map[string]string) func(string) string {
	return func(originalHost string) string {
		originalHost, _ = splitHost(originalHost)

		forwardingHost := defaultForwardingURL.Host

		if host, ok := addrMap[originalHost]; ok {
			forwardingHost = host
		}

		return forwardingHost
	}
}

func splitHost(host string) (string, error) {
	parts := strings.SplitN(host, ":", 2)

	if len(parts) == 0 {
		return "", fmt.Errorf("Host header not specified")
	}

	return parts[0], nil
}
