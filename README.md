bmcldap [![Go Report Card](https://goreportcard.com/badge/github.com/bmc-toolbox/bmcldap)](https://goreportcard.com/report/github.com/bmc-toolbox/bmcldap)
=======

What?
----

A LDAP to LDAP proxy, to Support LDAP authentication and authorization for BMC devices.

Every hardware vendor has BMC devices that require special LDAP attributes/or expect LDAP directory trees which are different from each other they may also require magical attributes not documented anywhere, to get around this bmcldap
runs as a ldap service, that identifies the vendor and figures out how it needs to deal with them.

How?
----
bmcldap sits in between the BMCs and the LDAP server, it looks at each request, and based on the vendor sets up the request for the backend and the appropriate response for the BMC.

Supported BMCs
--------------
    HP - iLO4,5
    Supermicro
    Dell - iDrac8

Configuration
-------------
a. bmcldap

    See the sample configuration file.

    A root CA certs (server.pem, server-key.pem) to authenticate ldap clients (BMCs in this case) see the snakeoil directory for certs to test with.


b. BMC configuration

*iDrac*
```
iDrac Settings -> User Authentication
 Enable Generic LDAP
 Use DN to Search Group Membership
 LDAP Server Address
 LDAP Server Port
 Bind DN : "dell"
 Bind Password: ""
 Base DN to Search: "cn=dell"
 Attribute of User Login: "uid"
 Attribute of Group Membership: "memberUid"
 Search Filter: "objectClass=posixAccount"

Role Group Privileges, create groups,
 Group DN: "cn=dell,cn=bmcAdmins"
 Group DN: "cn=dell,cn=bmcUsers"
```

*iLO*
```
Directory groups:
  - cn=hp,cn=bmcAdmins
  - cn=hp,cn=bmcUsers

Security -> Directory -> Authentication Options
 Enable Local User Accounts

Security -> Directory -> Directory Server settings
 Enable Generic LDAP
 Set Directory Server Address
 Set Directory Server LDAP Port
```

*Supermicro*
Supermicro BMCs only allow addition of a single ldap group.
```
Configuration -> Ldap
 Enable LDAP Authentication
 Port: LDAP/LDAPs port
 IP Address: LDAP server address
 Bind Password: leave undefined
 Bind DN: "supermicro"
 Search Base: "cn=supermicro,cn=bmcUsers"
```

Build
-----
`GO111MODULE=on go build -mod vendor -v`

Run
---

```
./bmcldap serve -c /etc/bmcldap/bmcldap.yml

#enable debug output
./bmcldap serve -d -c /etc/bmcldap/bmcldap.yml
```

Debugging
---------

pprof http endpoint runs on localhost:6060

sending a `SIGUSR1` to the process PID will dump memstats and number of goroutines.

Acknowledgement
---------------
bmcldap was originally developed for [Booking.com](http://www.booking.com).
With approval from [Booking.com](http://www.booking.com), the code and
specification were generalized and published as Open Source on github, for
which the authors would like to express their gratitude.
