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

package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
)

// EdgeHTTPProxy starts serving the proxy requests via proxyForEdge (http.request).
func EdgeHTTPProxy(forwardingAddress func(string) string, caList *x509.CertPool, clientCert *tls.Certificate, proxyForEdge func(*http.Request) (*url.URL, error)) http.Handler {
	proxy := SmartHTTPProxy(forwardingAddress, caList, clientCert, proxyForEdge)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyURL := &url.URL{
			Scheme: r.URL.Scheme,
			Host:   forwardingAddress(r.Host),
		}
		fmt.Printf("%s %s -> %s\n", r.Method, r.URL.RequestURI(), proxyURL.ResolveReference(r.URL))

		proxy.ServeHTTP(w, r)
	})
}
