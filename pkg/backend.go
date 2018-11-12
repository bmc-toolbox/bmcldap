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

package pkg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/bmc-toolbox/bmcldap/pkg/providers/dell"
	"github.com/bmc-toolbox/bmcldap/pkg/providers/generic"
	"github.com/bmc-toolbox/bmcldap/pkg/providers/hp"
	"github.com/bmc-toolbox/bmcldap/pkg/providers/supermicro"
	servercontext "github.com/bmc-toolbox/bmcldap/pkg/servercontext"

	"github.com/samuel/go-ldap/ldap"
)

type Authenticator interface {
	Authenticate(ctx context.Context, bindDN string, bindPassword []byte) bool
	Authorize(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.SearchResult, error)
}

type session struct {
	context context.Context
	cancel  context.CancelFunc
}

func (bmcLdap *BmcLdap) Bind(ctx ldap.Context, req *ldap.BindRequest) (bindResponse *ldap.BindResponse, err error) {

	log := bmcLdap.logger

	if req.DN == "" {
		return nil, errInvalidBindDN
	}

	sess, ok := ctx.(*session)
	if !ok {
		return nil, errInvalidSessionType
	}

	log.Debug(fmt.Sprintf("BIND request: %s", req.DN))

	//setup the response
	bindResponse = &ldap.BindResponse{
		BaseResponse: ldap.BaseResponse{
			Code: ldap.ResultInvalidCredentials,
		},
	}

	sess.context = servercontext.SetDn(sess.context, "")

	var bindUsername string
	var bindPassword []byte

	bindUsername = req.DN
	bindPassword = req.Password

	var auth Authenticator
	switch bindUsername {
	case "supermicro":
		auth = &supermicro.Supermicro{Logger: bmcLdap.logger, Config: bmcLdap.config}
	case "dell":
		auth = &dell.Dell{Logger: bmcLdap.logger, Config: bmcLdap.config}
	default:
		auth = &generic.Generic{Logger: bmcLdap.logger, Config: bmcLdap.config}

	}

	//defer remoteLdapClient.Close()

	//Since HP iLOs will attempt the first BIND with just the username,
	//we look for strings that don't seem to be a DN
	var bindDN string
	if strings.Contains(bindUsername, "=") == false {
		bindDN = fmt.Sprintf("uid=%s,%s", bindUsername, bmcLdap.config.BaseDN)
	} else {
		bindDN = bindUsername
	}
	if auth.Authenticate(sess.context, bindDN, bindPassword) {
		sess.context = servercontext.SetDn(sess.context, req.DN)
		bindResponse.BaseResponse.Code = ldap.ResultSuccess
		bindResponse.MatchedDN = req.DN

		log.Debug(fmt.Sprintf("Successful bind with remote ldap server for %s", bindDN))
		log.Debug(fmt.Sprintf("Bind accept response %#v", bindResponse))
		return bindResponse, err
	} else {
		log.Debug(fmt.Sprintf("BIND reject response %#v", bindResponse))
		return bindResponse, err
	}
}

func (bmcLdap *BmcLdap) Connect(remoteAddr net.Addr) (ldap.Context, error) {
	ctx, cancel := context.WithCancel(bmcLdap.context)
	log := bmcLdap.logger
	log.Debug(fmt.Sprintf("Client connected : %s", remoteAddr))

	session := &session{context: ctx, cancel: cancel}
	//session.context = servercontext.SetAddr(session.context, fmt.Sprintf("%s", remoteAddr))

	return session, nil
}

func (bmcLdap *BmcLdap) Disconnect(ctx ldap.Context) {
	sess, ok := ctx.(*session)
	if !ok {
		return
	}
	//log := bmcLdap.logger
	//	log.Debug(fmt.Sprintf("Client disconnected, user: %s, ip: %s",
	//		servercontext.GetDn(sess.context), servercontext.GetAddr(sess.context)))
	//bmcLdap.client.Close()
	sess.cancel()
}

func (bmcLdap *BmcLdap) Search(ctx ldap.Context, req *ldap.SearchRequest) (res *ldap.SearchResponse, err error) {
	sess, ok := ctx.(*session)
	if !ok {
		return nil, errInvalidSessionType
	}

	bmcLdap.logger.Debug(fmt.Sprintf("SEARCH request: %#v", req))
	if servercontext.GetDn(sess.context) == "" || req.BaseDN == "" {
		return &ldap.SearchResponse{
			BaseResponse: ldap.BaseResponse{
				Code: ldap.ResultInsufficientAccessRights,
			},
		}, nil
	}

	var auth Authenticator
	//identify vendor
	if strings.Contains(req.BaseDN, "cn=hp") {
		bmcLdap.logger.Debug(fmt.Sprintf("BMC identified as HP based on baseDN: %s", req.BaseDN))
		auth = &hp.Hp{Logger: bmcLdap.logger, Config: bmcLdap.config}
	}

	if strings.Contains(req.BaseDN, "cn=supermicro") {
		bmcLdap.logger.Debug(fmt.Sprintf("BMC identified as Supermicro based on baseDN: %s", req.BaseDN))
		auth = &supermicro.Supermicro{Logger: bmcLdap.logger, Config: bmcLdap.config}
	}

	if strings.Contains(req.BaseDN, "cn=dell") {
		bmcLdap.logger.Debug(fmt.Sprintf("BMC identified as Dell based on baseDN: %s", req.BaseDN))
		auth = &dell.Dell{Logger: bmcLdap.logger, Config: bmcLdap.config}
	}

	if auth == nil {
		return &ldap.SearchResponse{
			BaseResponse: ldap.BaseResponse{
				Code: ldap.ResultInsufficientAccessRights,
			},
		}, errors.New(fmt.Sprintf("Unrecognized vendor BaseDN: %s", req.BaseDN))
	}

	searchResults, err := auth.Authorize(sess.context, req)
	if err != nil {
		return &ldap.SearchResponse{
			BaseResponse: ldap.BaseResponse{
				Code: ldap.ResultInsufficientAccessRights,
			},
		}, err
	}

	res = &ldap.SearchResponse{
		BaseResponse: ldap.BaseResponse{
			Code:      ldap.ResultSuccess,
			MatchedDN: searchResults[0].DN,
		},
		Results: []*ldap.SearchResult{
			&ldap.SearchResult{
				DN:         searchResults[0].DN,
				Attributes: searchResults[0].Attributes,
			},
		},
	}

	return res, err
}

func (bmcLdap *BmcLdap) Whoami(ctx ldap.Context) (string, error) {
	sess, ok := ctx.(*session)
	if !ok {
		return "", errInvalidSessionType
	}

	return servercontext.GetDn(sess.context), nil
}

// Method added to conform to ldap.Server interface
func (bmcLdap *BmcLdap) Add(ctx ldap.Context, req *ldap.AddRequest) (*ldap.AddResponse, error) {
	return &ldap.AddResponse{
		BaseResponse: ldap.BaseResponse{
			Code: ldap.ResultUnwillingToPerform,
		},
	}, nil
}

// Method added to conform to ldap.Server interface
func (bmcLdap *BmcLdap) Delete(ctx ldap.Context, req *ldap.DeleteRequest) (*ldap.DeleteResponse, error) {
	return &ldap.DeleteResponse{
		BaseResponse: ldap.BaseResponse{
			Code: ldap.ResultUnwillingToPerform,
		},
	}, nil
}

// Method added to conform to ldap.Server interface
func (bmcLdap *BmcLdap) ExtendedRequest(ctx ldap.Context, req *ldap.ExtendedRequest) (*ldap.ExtendedResponse, error) {
	return &ldap.ExtendedResponse{
		BaseResponse: ldap.BaseResponse{
			Code: ldap.ResultUnwillingToPerform,
		},
	}, nil
}

// Method added to conform to ldap.Server interface
func (bmcLdap *BmcLdap) Modify(ctx ldap.Context, req *ldap.ModifyRequest) (*ldap.ModifyResponse, error) {
	return &ldap.ModifyResponse{
		BaseResponse: ldap.BaseResponse{
			Code: ldap.ResultUnwillingToPerform,
		},
	}, nil
}

// Method added to conform to ldap.Server interface
func (bmcLdap *BmcLdap) ModifyDN(ctx ldap.Context, req *ldap.ModifyDNRequest) (*ldap.ModifyDNResponse, error) {
	return &ldap.ModifyDNResponse{
		BaseResponse: ldap.BaseResponse{
			Code: ldap.ResultUnwillingToPerform,
		},
	}, nil
}

// Method added to conform to ldap.Server interface
func (bmcLdap *BmcLdap) PasswordModify(ctx ldap.Context, req *ldap.PasswordModifyRequest) ([]byte, error) {

	return []byte{}, nil
}
