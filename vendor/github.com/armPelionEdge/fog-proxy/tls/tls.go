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
)

type CertStrategyConfig map[string]string
type CertificateBuilder func(settings CertStrategyConfig) (*tls.Certificate, <-chan *tls.Certificate, error)

var drivers map[string]CertificateBuilder = map[string]CertificateBuilder{
	FileCertDriverName: FileCertificateBuilder,
	TpmCertDriverName:  TpmCertificateBuilder,
}

func MakeCertificate(driver string, settings CertStrategyConfig) (*tls.Certificate, <-chan *tls.Certificate, error) {
	builder, ok := drivers[driver]

	if !ok {
		return nil, nil, fmt.Errorf("Unknown certificate strategy: %s", driver)
	}

	return builder(settings)
}

func Drivers() []string {
	driverNames := make([]string, 0, len(drivers))

	for name, _ := range drivers {
		driverNames = append(driverNames, name)
	}

	return driverNames
}

func DefaultDriver() string {
	return FileCertDriverName
}
