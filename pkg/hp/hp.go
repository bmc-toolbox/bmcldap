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

package hp

import (
	"context"
	"fmt"
	"strings"

	servercontext "github.com/bmc-toolbox/bmcldap/pkg/servercontext"
	"github.com/samuel/go-ldap/ldap"
	"github.com/sirupsen/logrus"
)

type Hp struct {
	LdapClient    *ldap.Client
	Logger        *logrus.Logger
	BaseDN        string
	AuthorizedDNs map[string]string
}

func (h *Hp) Authenticate(ctx context.Context, username string, password string) bool {

	//var bindUsername string
	//var bindPassword []byte

	return true
}

func (h *Hp) Authorize(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.SearchResult, error) {

	log := h.Logger
	searchResults := ldap.SearchResult{}
	username := servercontext.GetDn(ctx)

	//look up the group base DN in our map of authorized DNs
	for group, groupBaseDN := range h.AuthorizedDNs {
		var lookupDN string
		if strings.Contains(req.BaseDN, group) {
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

		log.Debug(fmt.Sprintf("Querying remote ldap with search request: %+v", searchRequest))
		sr, err := h.LdapClient.Search(&searchRequest)
		if err != nil {
			log.Warn(fmt.Sprintf("User: %s not in authorized group: %s", username, lookupDN))
			continue
		}

		log.Debug(fmt.Sprintf("Remote ldap search request result: %+v", sr))
		if len(sr) > 0 {
			sr[0].DN = req.BaseDN
			return sr, nil
		}

	}

	return []*ldap.SearchResult{&searchResults}, nil
}
