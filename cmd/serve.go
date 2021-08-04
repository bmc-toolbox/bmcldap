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

package cmd

import (
	"fmt"
	"sync"

	"github.com/bmc-toolbox/bmcldap/pkg"
	"github.com/bmc-toolbox/bmcldap/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start LDAP service",
	Run: func(cmd *cobra.Command, args []string) {
		serve()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func serve() {
	//TODO: add config validator
	config := config.Config{
		BaseDN:                  viper.GetString("BaseDN"),
		ClientCaCert:            viper.GetString("ClientCaCert"),
		RemoteServerName:        viper.GetString("RemoteServerName"),
		RemoteServerPortTLS:     viper.GetInt("RemoteServerPortTLS"),
		Debug:                   viper.GetBool("Debug"),
		MinTLSVersion:           viper.GetString("MinTLSVersion"),
		PortTLS:                 viper.GetInt("PortTLS"),
		PortInsecure:            viper.GetInt("PortInsecure"),
		Cert:                    viper.GetString("Cert"),
		Key:                     viper.GetString("Key"),
		Prefixes:                viper.GetStringSlice("Prefixes"),
		SuperMicroAuthorizedDNs: viper.GetStringMapString("SuperMicroAuthorizedDNs"),
		IgnoreFilters:           viper.GetStringSlice("IgnoreFilters"),
	}

	// To ease the abstraction, an empty prefix always exists.
	if config.Prefixes == nil {
		config.Prefixes = []string{""}
	} else {
		found := false
		for _, prefix := range config.Prefixes {
			if prefix == "" {
				found = true
				break
			}
		}
		if !found {
			config.Prefixes = append([]string{""}, config.Prefixes...)
		}
	}

	server := pkg.NewLdapServer(logger, &config)
	var wg sync.WaitGroup

	wg.Add(2)

	ldapsAddr := fmt.Sprintf(":%d", config.PortTLS)
	ldapAddr := fmt.Sprintf(":%d", config.PortInsecure)

	tlsConfig := server.LoadTlsConfig(&config)
	go server.Ldaps("tcp", ldapsAddr, tlsConfig)
	go server.Ldap("tcp", ldapAddr)

	wg.Wait()
}
