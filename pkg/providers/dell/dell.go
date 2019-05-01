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
//2. BMC performs a search with the username, bmcldap returns a DN that the BMC will use to Bind
//
//3. BMC binds with the returned DN in the above search result
//
//4. BMC does a search for each ldap role group configured,
//   bmcldap in turn, "fixes" up the DN and looks up the username in the ldap server.

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
//
import (
	"context"
	"fmt"
	"strings"

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

func extractUsername(s string) (string, error) {

	var parts []string

	if strings.Contains(s, "objectClass") {
		// split out username component from the filter request
		// sample string: (&(uid=johndoe)(objectClass=posixAccount))

		parts = strings.Split(s, "uid=")
		if len(parts) < 2 {
			return "", fmt.Errorf("Unexpected string")
		}

		parts = strings.Split(parts[1], ")")
	} else {
		//(memberUid=uid\3djohndoe,ou\3dPeople,dc\3dexample,dc\3dcom)
		parts = strings.Split(s, ",")
		parts = strings.Split(parts[0], "(memberUid=uid\\3d")
		parts[0] = parts[1]
	}

	if len(parts) == 0 {
		return "", fmt.Errorf("no username in string")
	} else {
		if parts[0] == "" {
			return "", fmt.Errorf("Empty username in string")
		}
	}

	return parts[0], nil
}

func (d *Dell) Authorize(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.SearchResult, error) {

	var searchResults = ldap.SearchResult{}

	ldapClient, err := ConnectRemoteServer(ctx, d.Config.ClientCaCert, d.Config.RemoteServerName, d.Config.RemoteServerPortTLS)
	if err != nil {
		d.Logger.Warn(err)

		return []*ldap.SearchResult{&searchResults}, err
	}

	defer ldapClient.Close()

	// 1. first search request - bmcldap responds with the user BaseDN the BMC should use to Bind.
	// The first search request after the bind with the cn=dell BaseDN,
	// we need to return the bindDN with the username thats part of the request filter,
	// this will cause the BMC to use the DN in the search result to bind with the returned user baseDN.
	if req.BaseDN == "cn=dell" {

		username, err := extractUsername(fmt.Sprintf("%s", req.Filter))
		if err != nil {
			d.Logger.Warn("Unable to extract username from filter.")
			return []*ldap.SearchResult{}, err
		}

		var r = ldap.SearchResult{DN: fmt.Sprintf("uid=%s,%s", username, d.Config.BaseDN),
			Attributes: make(map[string][][]byte)}

		return []*ldap.SearchResult{&r}, nil
	}

	//2. BMC binds with the DN returned in the search result. (handled by the Bind() interface method)

	//3. The subsequent search request we iterate over the configured LDAP role groups,
	// if the username is a member of either of those groups return true
	//look up the group base DN in our map of authorized DNs
	for group, groupBaseDN := range d.Config.AuthorizedDNs {

		var lookupDN string
		if strings.Contains(strings.ToLower(req.BaseDN), group) {
			lookupDN = groupBaseDN
		} else {
			continue
		}

		username, err := extractUsername(fmt.Sprintf("%s", req.Filter))
		if err != nil {
			d.Logger.Warn(fmt.Printf("Unable to extract username from filter: %s", err))
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

		d.Logger.Debug(fmt.Sprintf("Querying remote LDAP with search request: %+v", searchRequest))
		sr, err := ldapClient.Search(&searchRequest)
		if err != nil {
			d.Logger.Warn(fmt.Sprintf("Remote LDAP search request returned an err: %s", err))
			return sr, err
		}

		if len(sr) > 0 {
			sr[0].DN = fmt.Sprintf("uid=%s,%s", username, d.Config.BaseDN)
			return sr, nil
		}

		d.Logger.Info(fmt.Sprintf("User %s not found in group %s", username, lookupDN))
	}

	return []*ldap.SearchResult{&searchResults}, fmt.Errorf("User not found in required ldap group(s).")
}
