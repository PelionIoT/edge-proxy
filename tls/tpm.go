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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/armPelionEdge/edge-proxy/rpc"
)

// cert strategy options
const (
	TpmCertDriverName           = "tpm"
	TpmJSONRPCSocket            = "socket"
	TpmJSONRPCPath              = "path"
	TpmDeviceCertName           = "device-cert-name"
	TpmPrivateKeyName           = "private-key-name"
	TpmCertRenewalQueryDuration = "cert-renewal-query-duration"
)

// JSON RPC API call method names
const (
	getCertMethod    = "crypto_get_certificate"
	ptRegisterMethod = "protocol_translator_register"
	cryptoSignMethod = "crypto_asymmetric_sign"
)

var (
	errInvalidECPublicKey      = errors.New("failed to convert the interface to ecdsa public key")
	errInvalidECSignature      = errors.New("invalid ecdsa signature")
	certRenewalWatcherDuration = 60
)

// the implementation of crypto.Signer interface
type ecdsaPrivateKey struct {
	certName       string
	privateKeyName string
	publicKey      crypto.PublicKey
	client         *rpc.Client
}

type ptRegisterArgs struct {
	Name string `json:"name"`
}

type getCertArgs struct {
	Certificate string `json:"certificate"`
}

type certificate struct {
	Data string `json:"certificate_data"`
	Name string `json:"certificate_name"`
}

// generateProtocolName generate the name for each JSON-RPC client registered as a protocal translator
func generateProtocolName() string {
	rb := make([]byte, 10)
	rand.Read(rb)

	return base64.URLEncoding.EncodeToString(rb)
}

func TpmCertificateBuilder(settings CertStrategyConfig) (*tls.Certificate, <-chan *tls.Certificate, error) {
	renewals := make(chan *tls.Certificate)

	fail := func(err error) (*tls.Certificate, chan *tls.Certificate, error) {
		return &tls.Certificate{}, renewals, err
	}

	wg := new(sync.WaitGroup)
	client := newJSONRPCClient(settings[TpmJSONRPCSocket], settings[TpmJSONRPCPath], wg)
	wg.Wait()

	tlsCert, err := configureTLSCert(client, settings)
	if err != nil {
		return fail(err)
	}

	if duration, ok := settings[TpmCertRenewalQueryDuration]; ok {
		i, err := strconv.Atoi(duration)

		if err != nil {
			fmt.Printf("Invalid certificate renewal query duration")
		}

		certRenewalWatcherDuration = i
	}

	go func() {
		for {
			<-time.After(time.Second * time.Duration(certRenewalWatcherDuration))
			fmt.Printf("Monitoring the certificate renewal\n")

			newTLSCert, err := configureTLSCert(client, settings)
			if err != nil {
				fmt.Printf("Unable to configure the TLS certificate. Error: %s\n", err.Error())

				continue
			}

			if newTLSCert.Leaf.SerialNumber.Cmp(tlsCert.Leaf.SerialNumber) != 0 {
				tlsCert = newTLSCert

				renewals <- &newTLSCert

				fmt.Printf("Detected a new certificate and the proxy server would be re-launched within %d seconds...\n", certRenewalWatcherDuration)
			}
		}
	}()

	return &tlsCert, renewals, nil
}

func configureTLSCert(client *rpc.Client, settings CertStrategyConfig) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) {
		return tls.Certificate{}, err
	}

	var tlsCert tls.Certificate

	var cert certificate
	if err := client.Call(getCertMethod, getCertArgs{Certificate: settings[TpmDeviceCertName]}, &cert); err != nil {
		return fail(err)
	}

	// since there is only one block of data, it is not necessary to look up the rest of the blocks
	certPEMBlock := []byte(attachHeaderAndFooter(cert.Data))
	certDERBlock, _ := pem.Decode(certPEMBlock)
	tlsCert.Certificate = append(tlsCert.Certificate, certDERBlock.Bytes)

	// parse the certificate as a X.509 certificate and pass into the leaf of tls certificate
	leafCert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return fail(err)
	}
	tlsCert.Leaf = leafCert

	// extract the public key of the x.509 cert
	pk, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fail(errInvalidECPublicKey)
	}

	// pass the implementaion of ecdsaPrivateKey as an opaque private key of the cert
	tlsCert.PrivateKey = &ecdsaPrivateKey{
		certName:       settings[TpmDeviceCertName],
		privateKeyName: settings[TpmPrivateKeyName],
		publicKey:      pk,
		client:         client,
	}

	return tlsCert, nil
}

func newJSONRPCClient(socket string, path string, wg *sync.WaitGroup) *rpc.Client {
	wg.Add(1)

	onConn := func(c *rpc.Client) error {
		defer wg.Done()

		var r string
		if err := c.Call(ptRegisterMethod, ptRegisterArgs{Name: generateProtocolName()}, &r); err != nil || r != "ok" {
			return err
		}

		return nil
	}

	return rpc.Dial(socket, path, onConn)
}

func (pk *ecdsaPrivateKey) Public() crypto.PublicKey {
	return pk.publicKey
}

type cryptoSignArgs struct {
	PrivateKeyName string `json:"private_key_name"`
	HashDigest     string `json:"hash_digest"`
}

type signature struct {
	Data string `json:"signature_data"`
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (pk *ecdsaPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var sig signature
	signArgs := cryptoSignArgs{PrivateKeyName: pk.privateKeyName, HashDigest: base64.StdEncoding.EncodeToString(digest)}

	if err := pk.client.Call(cryptoSignMethod, signArgs, &sig); err != nil {
		return nil, err
	}

	// signature data is a base64 encoded string of a RAW format ecdsa signature
	raw, err := base64.StdEncoding.DecodeString(sig.Data)
	if err != nil {
		return nil, err
	}

	// signature data should be encoded as DER-encoded ASN.1 format
	if len(raw) != 64 {
		return nil, errInvalidECSignature
	}

	return asn1.Marshal(ecdsaSignature{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
}

func attachHeaderAndFooter(data string) string {
	return fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", data)
}
