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

//HP BMC LDAP auth steps
// HP BMCs are identified by the Base DN
//1. BMC Binds with login username (Authentication)
//  - bmcldap will use the 'generic' Authenticate method to bind with the remote ldap server
//2. BMC Searches the Search Base for the configured ldap groups - cn=hp,cn=bmcAdmins / cn=hp,cn=bmcUsers (Authorization) - bmcldap passes the search request to the 'hp' Authorize method to lookup the user in the configured Groups.

//Configuration
//Directory groups:
//  - cn=hp,cn=bmcAdmins
//  - cn=hp,cn=bmcUsers
//Directory User context 1
//  - cn=hp
//Security -> Directory -> Authentication Options
// Enable Local User Accounts
//Security -> Directory -> Directory Server settings
// Enable Generic LDAP
// Set Directory Server Address
// Set Directory Server LDAP Port

package hp

import (
	"context"
	"fmt"
	"strings"

	"github.com/bmc-toolbox/bmcldap/pkg/config"
	"github.com/bmc-toolbox/bmcldap/pkg/providers"
	"github.com/bmc-toolbox/bmcldap/pkg/servercontext"
	"github.com/samuel/go-ldap/ldap"
	"github.com/sirupsen/logrus"
)

type Hp struct {
	Logger *logrus.Logger
	Config *config.Config
}

func (h *Hp) Authenticate(ctx context.Context, bindDN string, bindPassword []byte) bool {
	//HP authentication is handled by the generic handler.
	return true
}

func (h *Hp) Authorize(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.SearchResult, error) {

	searchResults := ldap.SearchResult{}
	username := servercontext.GetDn(ctx)

	ldapClient, err := providers.ConnectRemoteServer(ctx, h.Config.ClientCaCert, h.Config.RemoteServerName, h.Config.RemoteServerPortTLS)
	defer ldapClient.Close()

	if err != nil {
		h.Logger.Warn(err)
		return []*ldap.SearchResult{&searchResults}, err
	}

	//look up the group base DN in our map of authorized DNs
	for group, groupBaseDN := range h.Config.AuthorizedDNs {
		var lookupDN string

		if strings.Contains(strings.ToLower(req.BaseDN), group) {
			lookupDN = groupBaseDN
		} else {
			continue
		}

		for _, prefix := range h.Config.Prefixes {
			u := prefix + username
			filter := &ldap.EqualityMatch{
				Attribute: "memberUid",
				Value:     []byte(u),
			}

			searchRequest := ldap.SearchRequest{
				BaseDN:       lookupDN,
				Scope:        ldap.ScopeWholeSubtree,
				DerefAliases: ldap.DerefAlways,
				SizeLimit:    0,
				TimeLimit:    0,
				TypesOnly:    false,
				Filter:       filter,
				Attributes:   req.Attributes,
			}

			h.Logger.Debug(fmt.Sprintf("Querying remote LDAP with search request: %+v", searchRequest))
			sr, err := ldapClient.Search(&searchRequest)
			if err != nil {
				h.Logger.Warn(fmt.Sprintf("Remote LDAP search request returned an err: %s", err))
				continue
			}

			if len(sr) > 0 {
				h.Logger.Debug(fmt.Sprintf("Remote LDAP search response: %#v", sr))
				h.Logger.Info(fmt.Sprintf("User %s found in group %s", u, lookupDN))
				sr[0].DN = req.BaseDN
				return sr, nil
			}
		}

		h.Logger.Info(fmt.Sprintf("(Prefixed?) user %s not found in group %s", username, lookupDN))
	}

	return []*ldap.SearchResult{&searchResults}, nil
}
