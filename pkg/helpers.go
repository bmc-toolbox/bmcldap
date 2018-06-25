// Copyright © 2018 Joel Rebello <joel.rebello@booking.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkg

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// returns tls config with RootCA certs loaded
func clientTlsConfig(cert string, serverName string) (*tls.Config, error) {

	clientCAPool := x509.NewCertPool()

	certBytes, err := ioutil.ReadFile(cert)
	if err == nil {
		if loadPEMCert(clientCAPool, certBytes) {
			tlsConfig := &tls.Config{
				RootCAs:            clientCAPool,
				InsecureSkipVerify: true,
				ServerName:         serverName,
			}

			return tlsConfig, nil
		}
	}

	return nil, fmt.Errorf("Error loading CA cert %s: %s", cert, err)
}

func loadPEMCert(certPool *x509.CertPool, pemCerts []byte) (ok bool) {

	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		//XXX To fix.
		//We assume here CA is self-signed

		cert.IsCA = true
		certPool.AddCert(cert)
		ok = true
	}

	return ok
}
