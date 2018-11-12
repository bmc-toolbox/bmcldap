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

package dell

//Dell BMC LDAP auth steps
//1. BMC attempts to Bind with the defined Bind DN - Bind DN is set to "dell" to identify the vendor.
//    - bmcldap just returns success for this step.
//2. BMC Searches the BASE DN for the login username
//    - Base DN needs to be set to "cn=dell" - to identify the vendor.
//    - bmcldap rewrites the BASE DN in the search request to the one defined, in bmcldap configuration parameter - BaseDN.
//      the search request is then passed to the remote ldap server and the reply passed back to the BMC
//3. BMC Binds with username, password credentials. - uid=username,ou=People,dc=example,dc=com

//Configuration
//iDrac Settings -> User Authentication
// Enable Generic LDAP
// Use DN to Search Group Membership
// LDAP Server Address
// LDAP Server Port
// Bind DN : "dell"
// Bind Password: ""
// Base DN to Search: "cn=dell"
// Attribute of User Login: "uid"
// Attribute of Group Membership: "memberUid"
// Search Filter: "objectClass=posixAccount"
//Role Group Privileges, create groups,
// Group DN: "cn=dell,cn=bmcAdmins"
// Group DN: "cn=dell,cn=bmcUsers"

import (
	"context"
	"fmt"

	. "github.com/bmc-toolbox/bmcldap/pkg/config"
	. "github.com/bmc-toolbox/bmcldap/pkg/providers"

	"github.com/samuel/go-ldap/ldap"
	"github.com/sirupsen/logrus"
)

type Dell struct {
	Logger *logrus.Logger
	Config *Config
}

func (d *Dell) Authenticate(ctx context.Context, bindDN string, bindPassword []byte) bool {
	return true
}

func (d *Dell) Authorize(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.SearchResult, error) {

	searchResults := ldap.SearchResult{}
	req.BaseDN = d.Config.BaseDN

	ldapClient, err := ConnectRemoteServer(ctx, d.Config.ClientCaCert, d.Config.RemoteServerName, d.Config.RemoteServerPortTLS)
	if err != nil {
		d.Logger.Warn(err)

		return []*ldap.SearchResult{&searchResults}, err
	}

	defer ldapClient.Close()

	d.Logger.Debug(fmt.Sprintf("Querying remote LDAP with search request: %+v", req))
	sr, err := ldapClient.Search(req)
	if err != nil {
		d.Logger.Warn(fmt.Sprintf("Remote LDAP search request returned an err: %s", err))
		return sr, err
	}

	if len(sr) > 0 {
		d.Logger.Debug(fmt.Sprintf("Remote LDAP search response: %+v", sr[0]))
		return sr, nil
	}

	return []*ldap.SearchResult{&searchResults}, nil
}
