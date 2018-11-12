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
	"context"
	"crypto/tls"
	"errors"
	"os"

	. "github.com/bmc-toolbox/bmcldap/pkg/config"
	"github.com/samuel/go-ldap/ldap"
	"github.com/sirupsen/logrus"
)

var (
	errInvalidSessionType = errors.New("Invalid sessions type.")
	errInvalidBindDN      = errors.New("Invalid BIND DN.")
)

type BmcLdap struct {
	server  *ldap.Server
	client  *ldap.Client //Client connection to the remote ldap server
	logger  *logrus.Logger
	config  *Config
	context context.Context
}

// returns a ldap.Server
func NewLdapServer(logger *logrus.Logger, config *Config) *BmcLdap {
	ldapBackend := &BmcLdap{context: context.Background(), logger: logger, config: config}
	ldapBackend.server, _ = ldap.NewServer(ldapBackend, nil)
	return ldapBackend
}

func (bmcLdap *BmcLdap) Ldaps(protocol string, address string, tlsConfig *tls.Config) {
	bmcLdap.logger.WithFields(logrus.Fields{
		"component":      "Ldaps",
		"Listen address": address,
	}).Info("LDAPs service started.")

	bmcLdap.server.ServeTLS(protocol, address, tlsConfig)
}

func (bmcLdap *BmcLdap) Ldap(protocol string, address string) {
	bmcLdap.logger.WithFields(logrus.Fields{
		"component":      "Ldap",
		"Listen address": address,
	}).Info("LDAP service started.")
	bmcLdap.server.Serve(protocol, address)
}

func (bmcLdap *BmcLdap) LoadTlsConfig(c *Config) *tls.Config {
	cert, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		bmcLdap.logger.WithFields(logrus.Fields{
			"component": "LoadTlsConfig",
			"Cert":      c.Cert,
			"Key":       c.Key,
		}).Error("Unable to load server SSL cert, key pair.")
		os.Exit(1)
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
}
