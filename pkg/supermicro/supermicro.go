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

import (
	"context"
	"github.com/samuel/go-ldap/ldap"
)

type Supermicro struct{}

func (s *Supermicro) Authenticate(ctx context.Context, username string, password string) bool {
	return true
}

func (s *Supermicro) Authorize(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.SearchResult, error) {
	searchResults := ldap.SearchResult{}
	return []*ldap.SearchResult{&searchResults}, nil
}
