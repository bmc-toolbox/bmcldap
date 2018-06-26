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

package generic

import (
	"context"
	"fmt"
	"github.com/samuel/go-ldap/ldap"
	"github.com/sirupsen/logrus"
)

type Generic struct {
	LdapClient    *ldap.Client
	Logger        *logrus.Logger
	BaseDN        string
	AuthorizedDNs map[string]string
}

func (g *Generic) Authenticate(ctx context.Context, bindDN string, bindPassword []byte) bool {

	g.Logger.Debug(fmt.Sprintf("Attempting bind with remote ldap server for %s", bindDN))

	err := g.LdapClient.Bind(bindDN, bindPassword)
	if err != nil {
		g.Logger.Debug(fmt.Sprintf("BIND request rejected by remote LDAP server: %s", err))

		return false
	}

	return true
}

func (g *Generic) Authorize(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.SearchResult, error) {
	searchResults := ldap.SearchResult{}
	return []*ldap.SearchResult{&searchResults}, nil
}
