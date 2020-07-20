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
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
)

func splitAddr(host string) (string, string, int, error) {
	parts := strings.SplitN(host, ":", 2)

	if len(parts) == 0 {
		return "", "", 0, fmt.Errorf("Host header not specified")
	}

	var port int

	if len(parts) == 1 {
		port = 80
	} else {
		p, err := strconv.Atoi(parts[1])

		if err != nil {
			return "", "", 0, fmt.Errorf("Host header contained invalid port number %s: %s", parts[1], err.Error())
		}

		port = p
	}

	hostParts := strings.SplitN(parts[0], ".", 2)

	if len(hostParts) != 2 {
		return "", "", 0, fmt.Errorf("Host header contained an invalid host specification %s", parts[0])
	}

	return hostParts[0], hostParts[1], port, nil
}

func EdgeTransport(caList *x509.CertPool, clientCert *tls.Certificate, proxyForEdge func(*http.Request) (*url.URL, error)) *http.Transport {
	t := &http.Transport{
		Proxy: proxyForEdge,
		TLSClientConfig: &tls.Config{
			RootCAs: caList,
			GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return clientCert, nil
			},
		},
	}

	err := http2.ConfigureTransport(t)

	if err != nil {
		fmt.Printf("Could not enable HTTP/2 on proxy transport: %s\n", err.Error())
	}

	return t
}
