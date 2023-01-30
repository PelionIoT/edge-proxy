/*
Copyright (c) 2020, Arm Limited and affiliates.
Copyright (c) 2023, Izuma Networks

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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/ext/auth"
)

/*
 * The purpose of this feature is  to allow tunneling of arbitrary HTTP(S) connections.
 * One use case for this is to allow tunneling of all Izuma edge traffic over an authenticated
 * proxy, so that we can function behind restrictive firewalls that only allow HTTP(S)
 * traffic to pass through them.  As opposed to adding tuneling code to each service, it
 * would be easier to have edge-proxy handle tunneling configuration in one place.
 */

// HTTPTunnelConfig for keeping track of HTTP connection details
type HTTPTunnelConfig struct {
	Addr          string
	ExternalProxy string
	RootCAFile    string
}

// StartHTTPTunnel starts a server that accepts to the HTTP CONNECT method to proxy arbitrary TCP connections.
// It can be used to tunnel HTTPS connections.
func StartHTTPTunnel(config *HTTPTunnelConfig) error {
	return StartHTTPSTunnel(&HTTPSTunnelConfig{
		Addr:          config.Addr,
		ExternalProxy: config.ExternalProxy,
		RootCAFile:    config.RootCAFile,
	})
}

// HTTPSTunnelConfig keeps track of HTTPS tunnel configurations (certs, username/passwd, ...)
type HTTPSTunnelConfig struct {
	Addr          string
	ExternalProxy string
	RootCAFile    string
	CertFile      string
	KeyFile       string
	Username      string
	Password      string
}

// StartHTTPSTunnel - start HTTPS Tunnel for Edge
func StartHTTPSTunnel(config *HTTPSTunnelConfig) error {
	proxy := goproxy.NewProxyHttpServer()

	if config.ExternalProxy != "" {
		u, err := url.Parse(config.ExternalProxy)
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
		if config.RootCAFile != "" {
			// Use user defined root CA
			certs, err := ioutil.ReadFile(config.RootCAFile)
			if err != nil {
				log.Printf("HTTP(S) Tunnel: failed to read root CA file: %s\n", err.Error())
				return err
			}

			rootCAPool := x509.NewCertPool()
			ok := rootCAPool.AppendCertsFromPEM(certs)
			if !ok {
				log.Printf("HTTP(S) Tunnel: failed to parse root CA file: %s\n", config.RootCAFile)
				return errors.New("failed to parse root CA certificate file")
			}

			proxy.Tr.TLSClientConfig.RootCAs = rootCAPool
		}
		proxy.ConnectDial = proxy.NewConnectDialToProxyWithHandler(config.ExternalProxy, func(req *http.Request) {
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

	if config.Username != "" || config.Password != "" {
		auth.ProxyBasic(proxy, "tunnel", func(user, passwd string) bool {
			authorized := (user == config.Username && passwd == config.Password)
			log.Printf("HTTP Tunnel: authorized=%t\n", authorized)
			return authorized
		})
	}

	if config.CertFile == "" || config.KeyFile == "" {
		log.Printf("HTTP Tunnel: starting a plain HTTP tunnel on %s\n", config.Addr)
		err := http.ListenAndServe(config.Addr, proxy)
		if err != nil {
			log.Printf("HTTP Tunnel encountered an error while starting: %s\n", err.Error())
			return err
		}
	} else {
		log.Printf("HTTP Tunnel: starting HTTP tunnel over TLS on %s\n", config.Addr)
		err := http.ListenAndServeTLS(config.Addr, config.CertFile, config.KeyFile, proxy)
		if err != nil {
			log.Printf("HTTP Tunnel over TLS encountered an error while starting: %s\n", err.Error())
			return err
		}
	}

	// Should not get here
	return nil
}
