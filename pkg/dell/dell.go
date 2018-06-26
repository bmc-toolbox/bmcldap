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
//1. Bind                          - Bind DN needs to be set to "dell"
//2. Searches the BASE DN          -  Base DN needs to be set to "cn=dell"
//3. Binds with username, password credentials. - uid=username,ou=People,dc=example,dc=com

import (
	"context"
	"fmt"

	"github.com/samuel/go-ldap/ldap"
	"github.com/sirupsen/logrus"
)

type Dell struct {
	LdapClient    *ldap.Client
	Logger        *logrus.Logger
	BaseDN        string
	AuthorizedDNs map[string]string
}

func (d *Dell) Authenticate(ctx context.Context, bindDN string, bindPassword []byte) bool {
	return true
}

func (d *Dell) Authorize(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.SearchResult, error) {

	searchResults := ldap.SearchResult{}
	req.BaseDN = d.BaseDN
	d.Logger.Debug(fmt.Sprintf("Querying remote LDAP with search request: %+v", req))
	sr, err := d.LdapClient.Search(req)
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
