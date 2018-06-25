bmcldap
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
    HP
    Supermicro (WIP)

Configuration
-------------
a. bmcldap

    See the sample configuration file.

    A root CA certs (server.pem, server-key.pem) to authenticate ldap clients (BMCs in this case) see the snakeoil directory for certs to test with.


b. ldap clients (BMCs in this case)

    HP
        Group directory search base : cn=hp,cn=bmcUsers
        CA client certs needs to be uploaded (see snakeoil dir for certs to test with)
        ldaps works

    Supermicro
        Search base: cn=Supermicro,cn=bmcUsers
        ldaps not tested, plain ldap works.

Run
---

./bmcldap -c /etc/bmcldap/bmcldap.yml

Acknowledgement
---------------
bmcldap was originally developed for [Booking.com](http://www.booking.com).
With approval from [Booking.com](http://www.booking.com), the code and
specification were generalized and published as Open Source on github, for
which the authors would like to express their gratitude.
