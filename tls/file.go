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

package tls

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
)

const FileCertDriverName = "file"
const FileCertDriverCertKey = "cert"
const FileCertDriverKeyKey = "key"

func FileCertificateBuilder(settings CertStrategyConfig) (*tls.Certificate, <-chan *tls.Certificate, error) {
	certFile, keyFile, err := fileCertificateSettings(settings)

	renewals := make(chan *tls.Certificate)

	if err != nil {
		return nil, renewals, err
	}

	certificate, err := ioutil.ReadFile(certFile)

	if err != nil {
		return nil, renewals, fmt.Errorf("Could not read file %s: %s", certFile, err.Error())
	}

	key, err := ioutil.ReadFile(keyFile)

	if err != nil {
		return nil, renewals, fmt.Errorf("Could not read file %s: %s", keyFile, err.Error())
	}

	cert, err := tls.X509KeyPair([]byte(certificate), []byte(key))

	if err != nil {
		return nil, renewals, fmt.Errorf("Invalid key pair: %s", err.Error())
	}

	return &cert, renewals, nil
}

func fileCertificateSettings(settings CertStrategyConfig) (string, string, error) {
	var certFile string
	var keyFile string
	var err error

	certFile, ok := settings[FileCertDriverCertKey]

	if !ok {
		return "", "", fmt.Errorf("Did not provide option %s", FileCertDriverCertKey)
	}

	keyFile, ok = settings[FileCertDriverKeyKey]

	if err != nil {
		return "", "", fmt.Errorf("Did not provide option %s", FileCertDriverKeyKey)
	}

	return certFile, keyFile, nil
}
