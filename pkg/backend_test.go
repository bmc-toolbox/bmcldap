package pkg

import (
	"github.com/samuel/go-ldap/ldap"
	"github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"

	"testing"

	. "github.com/bmc-toolbox/bmcldap/pkg/config"
)

type invalidSession struct{}

//setup requirements for test
func setup() (*Config, *logrus.Logger) {
	return &Config{
		BaseDN:              "ou=People,dc=example,dc=com",
		ClientCaCert:        "/etc/openldap/cacerts/cacert.pem",
		RemoteServerName:    "ldaps.example.com",
		RemoteServerPortTLS: 636,
		Debug:               true,
		MinTLSVersion:       "1.2",
		PortTLS:             443,
		PortInsecure:        386,
		Cert:                "/etc/bmcldap/server.pem",
		Key:                 "/etc/bmcldap/server-key.pem",
		AuthorizedDNs: map[string]string{
			"bmcUsers":  "cn=bmcUsers,ou=Group,dc=example,dc=com",
			"bmcAdmins": "cn=bmcAdmins,ou=Group,dc=example,dc=com",
		},
	}, logrus.New()

}

//Test connect
func TestBmcLdap_Connect(t *testing.T) {
	config, logger := setup()

	Convey("Given a ldap server", t, func() {
		server := NewLdapServer(logger, config)
		So(server, ShouldNotBeNil)

		Convey("When there is a new connection", func() {
			ctx, err := server.Connect(nil)
			Convey("A new session is created", func() {
				So(err, ShouldBeNil)

				session, ok := ctx.(*session)
				So(ok, ShouldBeTrue)
				So(session, ShouldNotBeNil)
			})
		})
	})
}

//Test Bind invalid bind DN
func TestBmcLdap_BindEmptyDN(t *testing.T) {
	config, logger := setup()
	Convey("Given a ldap server", t, func() {
		server := NewLdapServer(logger, config)
		Convey("When there is a bind request with an empty bindDN,", func() {
			_, err := server.Bind(&invalidSession{}, &ldap.BindRequest{DN: ""})
			Convey("An error should be returned", func() {
				So(err, ShouldEqual, errInvalidBindDN)
			})
		})
	})
}

//Test Bind invalid session
func TestBmcLdap_BindInvalidSession(t *testing.T) {

	config, logger := setup()
	Convey("Given a ldap server", t, func() {
		server := NewLdapServer(logger, config)
		Convey("When there is a bind request with a invalid session,", func() {
			id, err := server.Bind(&invalidSession{}, &ldap.BindRequest{DN: "Foobar"})
			Convey("An error should be returned", func() {
				So(err, ShouldEqual, errInvalidSessionType)
				So(id, ShouldBeNil)
			})
		})
	})
}

//Test Search
func TestBmcLdap_Search(t *testing.T) {
	config, logger := setup()
	Convey("Given a ldap server", t, func() {
		server := NewLdapServer(logger, config)
		Convey("When there is a search request with an invalid session, ", func() {

			filter := &ldap.EqualityMatch{
				Attribute: "memberUid",
				Value:     []byte("foo"),
			}

			searchRequest := ldap.SearchRequest{
				BaseDN:       "foo",
				Scope:        ldap.ScopeWholeSubtree,
				DerefAliases: ldap.DerefAlways,
				SizeLimit:    0,
				TimeLimit:    0,
				TypesOnly:    false,
				Filter:       filter,
				Attributes:   map[string]bool{"foo": true},
			}

			id, err := server.Search(&invalidSession{}, &searchRequest)
			Convey("An error should be returned", func() {
				So(err, ShouldEqual, errInvalidSessionType)
				So(id, ShouldBeNil)
			})
		})
	})
}
