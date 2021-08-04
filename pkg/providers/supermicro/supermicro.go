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

package supermicro

//Supermicro BMC LDAP auth steps
// Since the supermicro doesn't let use configure multiple role groups,
// only one role group is configured.
// We identify Supermicro BMCs by the Bind DN (compared to Idrac, iLOs which we identify by Base DN)
//1. Binds with configured Bind DN - Bind DN needs to be set to "supermicro"
//2. Searches on the Search Base    - Searchbase needs to be set to cn=supermicro,cn=bmcUsers
//3. Binds with username, password credentials.

//Configuration
//Configuration -> Ldap
// Enable LDAP Authentication
// Port: LDAP/LDAPs port
// IP Address: LDAP server address
// Bind Password: leave undefined
// Bind DN: "supermicro"
// Search Base: "cn=supermicro,cn=bmcUsers"

import (
	"context"
	"fmt"
	"strings"

	"github.com/bmc-toolbox/bmcldap/pkg/config"
	"github.com/bmc-toolbox/bmcldap/pkg/providers"
	"github.com/samuel/go-ldap/ldap"
	"github.com/sirupsen/logrus"
)

type Supermicro struct {
	Logger *logrus.Logger
	Config *config.Config
}

//When configuring the supermicro, use the 'supermicro' username
func (s *Supermicro) Authenticate(ctx context.Context, bindDN string, bindPassword []byte) bool {
	return true
}

func extractUsername(filter string) string {
	username := strings.Split(filter, "cn=")[1]
	username = strings.Trim(username, ")")
	return username
}

func (s *Supermicro) Authorize(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.SearchResult, error) {
	//sess, ok := ctx.(*servercontext.Session)
	//if !ok {
	//	return nil, errors.New("Invalid sessions type.")
	//}

	searchResults := ldap.SearchResult{}
	//In its first Search request, the supermicro does a search with the login username
	//as its search filter, here we extract the username from that request.
	//sess.context = servercontext.SetDn(sess.context, fmt.Sprintf("%s", req.Filter))
	username := extractUsername(req.Filter.String())

	ldapClient, err := providers.ConnectRemoteServer(ctx, s.Config.ClientCaCert, s.Config.RemoteServerName, s.Config.RemoteServerPortTLS)
	defer ldapClient.Close()

	if err != nil {
		s.Logger.Warn(err)
		return []*ldap.SearchResult{&searchResults}, err
	}

	//look up the group base DN in our map of authorized DNs
	for group, groupBaseDN := range s.Config.AuthorizedDNs {
		var lookupDN string

		if strings.Contains(strings.ToLower(req.BaseDN), group) {
			lookupDN = groupBaseDN
		} else {
			continue
		}

		filter := &ldap.EqualityMatch{
			Attribute: "memberUid",
			Value:     []byte(username),
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

		s.Logger.Debug(fmt.Sprintf("Querying remote LDAP with search request: %+v", searchRequest))
		sr, err := ldapClient.Search(&searchRequest)
		if err != nil {
			s.Logger.Warn(fmt.Sprintf("Remote LDAP search request returned an err: %s", err))
			continue
		}

		if len(sr) > 0 {
			s.Logger.Debug(fmt.Sprintf("Remote LDAP search response: %#v", sr))
			s.Logger.Info(fmt.Sprintf("User %s found in group %s", username, lookupDN))
			sr[0].DN = username
			//yeah! supermicro expects these special attributes
			sr[0].Attributes["permission"] = [][]byte{[]byte("H=4")}
			return sr, nil
		}

		s.Logger.Info(fmt.Sprintf("User %s not found in group %s", username, lookupDN))

	}

	return []*ldap.SearchResult{&searchResults}, nil
}
