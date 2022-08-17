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

package config

type Config struct {
	Debug               bool
	PortTLS             int
	PortInsecure        int
	BaseDN              string
	Config              string
	MinTLSVersion       string
	CipherSuites        []string
	RemoteServerName    string
	RemoteServerPortTLS int
	CaCert              string
	ClientCaCert        string
	Cert                string
	Key                 string
	IgnoreFilters       []string
	// The LDAP groups we want to authorize for SuperMicro.
	// It doesn't support multiple groups in the BMC.
	SuperMicroAuthorizedDNs map[string]string
	// Prefixes that might be useful, like temporary_fooUsers.
	// This is sometimes used for firefighting (granting temporary access rights during emergencies).
	Prefixes []string
}
