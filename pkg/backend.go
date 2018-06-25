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

	"github.com/bmc-toolbox/bmcldap/pkg/hp"
	servercontext "github.com/bmc-toolbox/bmcldap/pkg/servercontext"
	"github.com/samuel/go-ldap/ldap"
)

type Authenticator interface {
	Authenticate(ctx context.Context, username string, password string) bool
	Authorize(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.SearchResult, error)
}

func (bmcLdap *BmcLdap) Bind(ctx ldap.Context, req *ldap.BindRequest) (ldapResponse *ldap.BindResponse, err error) {

	log := bmcLdap.logger
	sess, ok := ctx.(*session)
	if !ok {
		return nil, errors.New("Invalid sessions type.")
	}

	log.Debug("BIND DN:", req.DN)

	//setup the response
	ldapResponse = &ldap.BindResponse{
		BaseResponse: ldap.BaseResponse{
			Code: ldap.ResultInvalidCredentials,
		},
	}

	sess.context = servercontext.SetDn(sess.context, "")

	var bindUsername string
	var bindPassword []byte

	bindUsername = req.DN
	bindPassword = req.Password

	remoteLdapClient, err := bmcLdap.ConnectRemoteServer()
	if err != nil {
		return ldapResponse, err
	}

	bindDN := fmt.Sprintf("uid=%s,%s", bindUsername, bmcLdap.config.BaseDN)
	log.Debug(fmt.Sprintf("Attempting bind with remote ldap server for %s", bindDN))

	err = remoteLdapClient.Bind(bindDN, bindPassword)
	if err != nil {
		return ldapResponse, err
	}

	//defer remoteLdapClient.Close()

	sess.context = servercontext.SetDn(sess.context, req.DN)
	ldapResponse.BaseResponse.Code = ldap.ResultSuccess
	ldapResponse.MatchedDN = req.DN

	log.Debug(fmt.Sprintf("Successful bind with remote ldap server for %s", bindDN))

	return ldapResponse, err
}

// Returns a client to a remote ldap server
func (bmcLdap *BmcLdap) ConnectRemoteServer() (client *ldap.Client, err error) {

	log := bmcLdap.logger

	tlsCfg, err := clientTlsConfig(bmcLdap.config.ClientCaCert, bmcLdap.config.RemoteServerName)
	if err != nil {
		log.Warn(fmt.Sprintf("Unable to connect to remote ldap server: %s", err))
		return client, err
	}

	serverAddress := fmt.Sprintf("%s:%d", bmcLdap.config.RemoteServerName, bmcLdap.config.RemoteServerPortTLS)
	client, err = ldap.DialTLS("tcp", serverAddress, tlsCfg)
	if err != nil {
		log.Warn(fmt.Sprintf("Unable to connect to remote ldap server: %s", err))
		return client, err
	}

	bmcLdap.client = client
	log.Debug("Connected to remote ldap server.")
	return client, err
}

func (bmcLdap *BmcLdap) Connect(remoteAddr net.Addr) (ldap.Context, error) {
	ctx, cancel := context.WithCancel(bmcLdap.context)
	log := bmcLdap.logger
	log.Debug(fmt.Sprintf("Client connected : %s", remoteAddr))

	session := &session{context: ctx, cancel: cancel}
	session.context = servercontext.SetAddr(session.context, fmt.Sprintf("%s", remoteAddr))

	return session, nil
}

func (bmcLdap *BmcLdap) Disconnect(ctx ldap.Context) {
	sess, ok := ctx.(*session)
	if !ok {
		return
	}
	log := bmcLdap.logger
	log.Debug(fmt.Sprintf("Client disconnected, user: %s, ip: %s",
		servercontext.GetDn(sess.context), servercontext.GetAddr(sess.context)))
	bmcLdap.client.Close()
	sess.cancel()
}

func (bmcLdap *BmcLdap) Search(ctx ldap.Context, req *ldap.SearchRequest) (res *ldap.SearchResponse, err error) {
	sess, ok := ctx.(*session)
	if !ok {
		return nil, errInvalidSessionType
	}

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
		auth = &hp.Hp{Logger: bmcLdap.logger,
			AuthorizedDNs: bmcLdap.config.AuthorizedDNs,
			LdapClient:    bmcLdap.client,
		}
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
