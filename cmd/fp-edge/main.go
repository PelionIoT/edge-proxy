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

	"github.com/armPelionEdge/fog-proxy-edge/cmd"
	"github.com/armPelionEdge/fog-proxy-edge/server"
	fog_tls "github.com/armPelionEdge/fog-proxy-edge/tls"
	"github.com/armPelionEdge/remotedialer"
	"github.com/gorilla/websocket"
)

const TunnelBackoffSeconds = 10
const ServerBackoffSeconds = 10

var tunnelURI string
var proxyURI string
var proxyAddr string
var ca string
var certStrategy string
var useL4Proxy bool
var certStrategyOptions cmd.OptionMap = cmd.OptionMap{}
var forwardingAddressesMap string

func main() {
	flag.StringVar(&tunnelURI, "tunnel-uri", "ws://localhost:8181/connect", "Tunnel address to connect to")
	flag.StringVar(&proxyURI, "proxy-uri", "", "Root URI to which outgoing HTTP requests should be proxied")
	flag.StringVar(&proxyAddr, "proxy-listen", "0.0.0.0:8080", "Listen address for HTTP proxy server")
	flag.BoolVar(&useL4Proxy, "use-l4-proxy", false, "Use a layer 4 proxy instead of a layer 7 proxy")
	flag.StringVar(&ca, "ca", "", "Certificate authority for the cloud")
	flag.StringVar(&certStrategy, "cert-strategy", fog_tls.DefaultDriver(), fmt.Sprintf("Certificate strategy must be one of: %v", fog_tls.Drivers()))
	flag.Var(&certStrategyOptions, "cert-strategy-options", "Can be specified one or more times. Must be a key-value pair (<key>=<value>)")
	flag.StringVar(&forwardingAddressesMap, "forwarding-addresses", "{}", "Forwarding address map that proxy server will use to proxy the requests to the corresponding host. Must be a json string")
	flag.Parse()

	if proxyURI == "" {
		fmt.Printf("proxy-uri must be provided\n")

		os.Exit(1)
	}

	proxyURIParsed, err := url.Parse(proxyURI)

	if err != nil {
		fmt.Printf("proxy-uri invalid: %s\n", err.Error())

		os.Exit(1)
	}

	if tunnelURI == "" {
		fmt.Printf("tunnel-uri must be provided\n")

		os.Exit(1)
	}

	var forwardingAddressesMapParsed map[string]string

	err = json.Unmarshal([]byte(forwardingAddressesMap), &forwardingAddressesMapParsed)

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

	ch := make(chan bool)

	certificate, renewals, err := fog_tls.MakeCertificate(certStrategy, fog_tls.CertStrategyConfig(certStrategyOptions))

	if err != nil {
		fmt.Printf("Unable to initialize client certificate: %s\n", err.Error())

		os.Exit(1)
	}

	go func() {
		for {
			fmt.Printf("Establishing fog-proxy tunnel (tunnelURI=%s)\n", tunnelURI)

			remotedialer.ClientConnect(tunnelURI, http.Header{}, &websocket.Dialer{
				NetDial: func(network, address string) (net.Conn, error) {
					netDialer := &net.Dialer{}
					return netDialer.Dial("tcp", proxyAddr)
				},
			}, func(string, string) bool { return true }, func(ctx context.Context) error {
				fmt.Printf("fog-proxy tunnel established\n")

				return nil
			})

			fmt.Printf("fog-proxy tunnel exited. Attempting to reestablish tunnel in %d seconds...\n", TunnelBackoffSeconds)

			time.Sleep(time.Second * TunnelBackoffSeconds)
		}
	}()

	go func(cert *tls.Certificate) {
		for {
			childCtx, cancelChildCtx := context.WithCancel(context.Background())

			go func() {
				c := <-renewals
				cert = c
				fmt.Print("fog-proxy received a renewal cert. Proxy server should be re-launched with the new cert...\n")

				cancelChildCtx()
			}()

			if useL4Proxy {
				fmt.Printf("Starting edge TLS proxy (proxyAddr=%s, proxyURI=%s)\n", proxyAddr, proxyURI)

				server.RunEdgeTLSProxyServer(childCtx, proxyAddr, proxyURIParsed, caList, cert)

				fmt.Printf("Edge TLS proxy server exited\n")
			} else {
				fmt.Printf("Starting edge HTTP proxy (proxyAddr=%s, proxyURI=%s)\n", proxyAddr, proxyURI)

				server.RunEdgeHTTPProxyServer(childCtx, proxyAddr, forwardingAddresses(proxyURIParsed, forwardingAddressesMapParsed), caList, cert)

				fmt.Printf("Edge HTTP proxy server exited\n")
			}

			fmt.Printf("fog-proxy proxy server shut down. Attemtping to re-launch proxy server in %d seconds...\n", ServerBackoffSeconds)

			<-time.After(time.Second * ServerBackoffSeconds)
		}
	}(certificate)

	<-ch
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

		fmt.Printf("Address map: %v. Current host: %s. Forwarding host: %s\n", addrMap, originalHost, forwardingHost)
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
