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

package rpc_test

import (
	"crypto/sha256"
	"encoding/base64"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/armPelionEdge/fog-proxy-edge/rpc"
)

type ptRegisterArgs struct {
	Name string `json:"name"`
}

type cryptoSignArgs struct {
	PrivateKeyName string `json:"private_key_name"`
	HashDigest     string `json:"hash_digest"`
}

type signResponse struct {
	Signature []byte `json:"signature_data"`
}

var _ = Describe("Client", func() {
	// please make sure to start edge-core locally to make sure the websocket server is running
	Specify("Make crypto asymmetric call to edge core", func() {
		client := Dial("/tmp/edge.sock", "/1/pt")
		defer client.Close()

		var res string
		err := client.Call("protocol_translator_register", ptRegisterArgs{Name: "test"}, &res)
		Expect(err).Should(BeNil())
		Expect(res).Should(Equal("ok"))

		keyName := "mbed.LwM2MDevicePrivateKey"
		data := "hashdata"
		hashData := sha256.Sum256([]byte(data))
		hashDigest := base64.StdEncoding.EncodeToString(hashData[:])
		args := cryptoSignArgs{
			PrivateKeyName: keyName,
			HashDigest:     hashDigest,
		}

		var signature signResponse
		err = client.Call("crypto_asymmetric_sign", args, &signature)
		Expect(err).Should(BeNil())
	})
})
