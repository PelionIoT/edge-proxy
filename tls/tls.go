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

package tls

import (
	"crypto/tls"
	"fmt"
)

// CertStrategyConfig map / string/string key-value pair storage
type CertStrategyConfig map[string]string

// CertificateBuilder function prototype
type CertificateBuilder func(settings CertStrategyConfig) (*tls.Certificate, <-chan *tls.Certificate, error)

var drivers map[string]CertificateBuilder = map[string]CertificateBuilder{
	FileCertDriverName: FileCertificateBuilder,
	TpmCertDriverName:  TpmCertificateBuilder,
}

// MakeCertificate creates certificates with given certificate strategy
func MakeCertificate(driver string, settings CertStrategyConfig) (*tls.Certificate, <-chan *tls.Certificate, error) {
	builder, ok := drivers[driver]

	if !ok {
		return nil, nil, fmt.Errorf("Unknown certificate strategy: %s", driver)
	}

	return builder(settings)
}

// Drivers for certificate builder
func Drivers() []string {
	driverNames := make([]string, 0, len(drivers))

	for name := range drivers {
		driverNames = append(driverNames, name)
	}

	return driverNames
}

// DefaultDriver returns default cert driver (FileCertDriverName)
func DefaultDriver() string {
	return FileCertDriverName
}
