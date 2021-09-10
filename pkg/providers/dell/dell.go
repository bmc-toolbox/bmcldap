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
//1. BMC attempts to Bind with the defined Bind DN - BMC is identified as Dell using the cn= attribute configured to cn=dell.
//2. BMC Searches the BASE DN for the login username to validate the account exists "objectClass=posixAccount"
//3. BMC Binds with the user BIND DN(uid=johndoe,ou=People,dc=example,dc=com),
//    using BaseDN "cn=dell,cn=fooUsers,ou=Group,dc=example,dc=com" and searches using the filter (memberUid=johndoe)

//Configuration
//iDrac Settings -> User Authentication
// Enable Generic LDAP
// Use DN to Search Group Membership !!!! This must be Disabled !!!!
// LDAP Server Address
// LDAP Server Port
// Bind DN : "dell"
// Bind Password: ""
// Base DN to Search: "cn=dell"
// Attribute of User Login: "uid"
// Attribute of Group Membership: "memberUid"
// Search Filter: "objectClass=posixAccount"
//Role Group Privileges, create groups,
// Group DN: "cn=dell,cn=bmcUsers,ou=Group,dc=example,dc=com"
// Group DN: "cn=dell,cn=bmcAdmins,ou=Group,dc=example,dc=com"

import (
	"context"
	"fmt"
	"strings"

	"github.com/bmc-toolbox/bmcldap/pkg/config"
	"github.com/bmc-toolbox/bmcldap/pkg/providers"
	"github.com/samuel/go-ldap/ldap"
	"github.com/sirupsen/logrus"
)

type Dell struct {
	Logger *logrus.Logger
	Config *config.Config
}

func (d *Dell) Authenticate(ctx context.Context, bindDN string, bindPassword []byte) bool {
	return true
}

func (d *Dell) Authorize(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.SearchResult, error) {
	searchResults := ldap.SearchResult{}

	ldapClient, err := providers.ConnectRemoteServer(ctx, d.Config.ClientCaCert, d.Config.RemoteServerName, d.Config.RemoteServerPortTLS)
	defer ldapClient.Close()

	if err != nil {
		d.Logger.Warn(err)
		return []*ldap.SearchResult{&searchResults}, err
	}

	d.Logger.Debug("Filter string is " + req.Filter.String())

	// Dell Search request 1: BMC validating the user account is present under the base DN.
	// Pass this request to the backend LDAP server and return the response to the client as is.
	if strings.Contains(req.Filter.String(), "objectClass=posixAccount") {
		// req.BaseDN at this point is set to "cn=dell".
		// This needs to be updated to a valid search base (starting point in the tree).
		req.BaseDN = d.Config.BaseDN

		d.Logger.Debug("Starting Dell Search 1 for " + req.BaseDN)
		searchResponse, err := ldapClient.Search(req)
		if err != nil {
			d.Logger.Warn(fmt.Sprintf("Remote LDAP search 1 request returned an error: %s", err))
		}
		return searchResponse, nil
	}

	// Dell Search request 2: BMC validating the user account is a member of the LDAP group.
	// Pass this request to the backend LDAP server and return the response to the client as is.
	if strings.Contains(req.Filter.String(), "memberUid=") {
		// req.BaseDN at this point would contain "cn=dell", to identify this BMC as Dell.
		// (e.g. "cn=dell,cn=fooUsers,ou=Group,dc=example,dc=com")
		d.Logger.Debug("Starting Dell Search 2 for " + req.BaseDN)

		// Strip out "cn=dell," from the request Base DN.
		mainDN := strings.Replace(req.BaseDN, "cn=dell,", "", 1)

		for _, prefix := range d.Config.Prefixes {
			req.BaseDN = strings.Replace(mainDN, "cn=", "cn="+prefix, -1)

			// Indicate that we have changed something...
			msg := "Performing actual search for " + req.BaseDN
			if prefix != "" {
				msg += " after adding " + prefix
			}
			d.Logger.Debug(msg)

			// The actual search.
			searchResponse, err := ldapClient.Search(req)
			if err != nil {
				d.Logger.Warn(fmt.Sprintf("Remote LDAP search 2 request returned an error: %s", err))
			}

			if len(searchResponse) > 0 {
				d.Logger.Debug(fmt.Sprintf("Found %v from Dell Search 2 for %v", searchResponse[0].DN, req.BaseDN))
				return searchResponse, nil
			}
		}
	}

	return []*ldap.SearchResult{&searchResults}, nil
}
