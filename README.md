# slapd-automember

An OpenLDAP slapd overlay module that synthesizes `member` and `memberOf` attributes on directories matching configured object classes.

## member

The `member` attribute is similar in intent to the `memberUid` attribute, but where the latter lists members by `uid` the former lists them by the `dn` of the user directory.  The `member` attribute is defined to be a *user attribute* in LDAP.

Since our tree already manages memberships using the `memberUid` attribute, explicitly adding the orthogonal `member` attribute would be cumbersome and prone to error; e.g. if a user's `uid` were to change, all `member` attributes referring to the original `uid` in their DN would have to be located and replaced.  The **automember** overlay responds to LDAP `Entry` objects of a configured object class (`groupOfNames` in our case) and applies all `memberUid` attributes to a template string, e.g.

```
uid={},ou=People,dc=hpc,dc=udel,dc=edu
```

to generate corresponding `member` DNs.  This simplification is permissible because we have a single-level directory of users, so no lookup of DN is required.  The entity is returned with the additional `member` attribute and values attached.

**PLEASE NOTE:** this method means that the `member` attribute is not usable in filters.

### Schema changes

Since the `groupOfNames` object class is structural under the default OpenLDAP schema, our existing groups could not simply have that object class added to them (nor could both `groupOfNames` and our `udRCIGroup` be present on a directory).  This was because the `posixGroup` object class (superclass of our `udRCIGroup`) is also structural.  The `groupOfNames` class requires at least one `member` attribute to be present:  a group using this structural class cannot have empty membership.  This is another inconvenience.

The solution was to alter our LDAP servers' schema to adapt the `groupOfNames` object class to our use case.  The same OID is used, but the type is shifted from structural to auxiliary and the `member` attribute was made optional.  This allowed all group directories to have the `groupOfNames` object class added.


## memberOf

The `memberOf` attribute provides a reference in a user directory to all groups to which the user is a member.  The `memberOf` attribute is defined to be a *operational attribute* in LDAP.

Synthesizing the `memberOf` attribute on a user directory of the configured object class (`udPerson` in our case) requires that the `uid` attribute value (which **must** be single-valued) be present and the object class for groups (used for the `member` attribute above) is configured.  These two values produce a filter

```
(&(objectClass=<class-name>)(uid=<uid-value>))
```

that is applied to an internal LDAP search operation against the entire backend database.  The DNs of the resulting entries are collected and form the `memberOf` attribute attached to the returned entry.

**PLEASE NOTE:** this method means that the `member` attribute is not usable in filters.

### Schema changes

The `memberOf` attribute is present in Microsoft's AD-oriented schema additions but is not available in the core schema definition as `member` is.  This overlay borrows from the logic of the **memberof** overlay and adds the `memberOf` attribute defintion via the module code (if it is not present in the configured schema) rather than relying on its being present in the configured schema.


## Building the module

The project includes a [Makefile](./Makefile) that mirrors the modules present in the OpenLDAP source tree under the `contrib/slapd-modules` path.  This repository can be cloned into the `contrib/slapd-modules` directory of an existing OpenLDAP source tree and the `make` command should work as expected therein.

By default the [Makefile](./Makefile) uses an install `prefix` of `/usr/local` and references the source code three directories up the parent chain (as `LDAP_SRC`).   Either of those variables can be modified to affect the build:

- pointing to an out-of-tree source path (`LDAP_SRC=/path/to/src/dir`)
- pointing to an alternative install prefix (`prefix=/path/to/install`)

For example:

```bash
[user@server automember]$ make prefix=/ldap/openldap/2.5.17 
../../../libtool --mode=compile gcc  -g3 -O0  -DSLAPD_OVER_AUTOMEMBER=SLAPD_MOD_DYNAMIC -I../../../include -I../../../include -I../../../servers/slapd -c automember.c
libtool: compile:  gcc -g3 -O0 -DSLAPD_OVER_AUTOMEMBER=SLAPD_MOD_DYNAMIC -I../../../include -I../../../include -I../../../servers/slapd -c automember.c  -fPIC -DPIC -o .libs/automember.o
libtool: compile:  gcc -g3 -O0 -DSLAPD_OVER_AUTOMEMBER=SLAPD_MOD_DYNAMIC -I../../../include -I../../../include -I../../../servers/slapd -c automember.c -o automember.o >/dev/null 2>&1
../../../libtool --mode=link gcc -g3 -O0  -version-info 0:0:0 -rpath /ldap/openldap/2.5.17/libexec/openldap -module -o automember.la automember.lo  ../../../libraries/libldap/libldap.la ../../../libraries/liblber/liblber.la
libtool: link: cc -shared  -fPIC -DPIC  .libs/automember.o   -Wl,-rpath -Wl,/ldap/openldap/2.5.17/src/libraries/libldap/.libs -Wl,-rpath -Wl,/ldap/openldap/2.5.17/src/libraries/liblber/.libs -Wl,-rpath -Wl,/ldap/openldap/2.5.17/lib -L/ldap/openldap/2.5.17/src/libraries/liblber/.libs ../../../libraries/libldap/.libs/libldap.so /ldap/openldap/2.5.17/src/libraries/liblber/.libs/liblber.so -lssl -lcrypto ../../../libraries/liblber/.libs/liblber.so  -g3 -O0   -Wl,-soname -Wl,automember.so.0 -o .libs/automember.so.0.0.0
libtool: link: (cd ".libs" && rm -f "automember.so.0" && ln -s "automember.so.0.0.0" "automember.so.0")
libtool: link: (cd ".libs" && rm -f "automember.so" && ln -s "automember.so.0.0.0" "automember.so")
libtool: link: ar cru .libs/automember.a  automember.o
libtool: link: ranlib .libs/automember.a
libtool: link: ( cd ".libs" && rm -f "automember.la" && ln -s "../automember.la" "automember.la" )
```

With a successful build, the module can be installed:

```
[user@server automember]$ make prefix=/ldap/openldap/2.5.17 install
mkdir -p /ldap/openldap/2.5.17/libexec/openldap
for p in automember.la ; do \
	../../../libtool --mode=install cp $p /ldap/openldap/2.5.17/libexec/openldap ; \
done
libtool: warning: relinking 'automember.la'
libtool: install: (cd /ldap/openldap/2.5.17/src/contrib/slapd-modules/automember; /bin/sh "/ldap/openldap/2.5.17/src/libtool"  --mode=relink gcc -g3 -O0 -version-info 0:0:0 -rpath /ldap/openldap/2.5.17/libexec/openldap -module -o automember.la automember.lo ../../../libraries/libldap/libldap.la ../../../libraries/liblber/liblber.la )
libtool: relink: cc -shared  -fPIC -DPIC  .libs/automember.o   -Wl,-rpath -Wl,/ldap/openldap/2.5.17/lib -L/ldap/openldap/2.5.17/src/libraries/liblber/.libs -L/ldap/openldap/2.5.17/lib -lldap -lssl -lcrypto -llber  -g3 -O0   -Wl,-soname -Wl,automember.so.0 -o .libs/automember.so.0.0.0
libtool: install: cp .libs/automember.so.0.0.0T /ldap/openldap/2.5.17/libexec/openldap/automember.so.0.0.0
libtool: install: (cd /ldap/openldap/2.5.17/libexec/openldap && { ln -s -f automember.so.0.0.0 automember.so.0 || { rm -f automember.so.0 && ln -s automember.so.0.0.0 automember.so.0; }; })
libtool: install: (cd /ldap/openldap/2.5.17/libexec/openldap && { ln -s -f automember.so.0.0.0 automember.so || { rm -f automember.so && ln -s automember.so.0.0.0 automember.so; }; })
libtool: install: cp .libs/automember.lai /ldap/openldap/2.5.17/libexec/openldap/automember.la
libtool: install: cp .libs/automember.a /ldap/openldap/2.5.17/libexec/openldap/automember.a
libtool: install: chmod 644 /ldap/openldap/2.5.17/libexec/openldap/automember.a
libtool: install: ranlib /ldap/openldap/2.5.17/libexec/openldap/automember.a
libtool: finish: PATH="/usr/share/Modules/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin" ldconfig -n /ldap/openldap/2.5.17/libexec/openldap
```

## Configuring the module

The overlay module must be loaded in the slapd configuration:

```
# Load dynamic modules:
moduleload automember.la
```

It is then activated within the context of a backend:

```
#######################################################################
# MDB database definitions
#######################################################################

database        mdb
   :
# automember:
overlay automember
automember-member-objectclass groupOfNames
automember-memberof-objectclass udPerson
automember-synth-template uid={},ou=People,dc=hpc,dc=udel,dc=edu

```

Lacking a configured `automember-member-objectclass` value, the overlay will **not** do anything; if only the `automember-memberof-objectclass` is not configured then the `memberOf` synthesis is disabled.  Lacking a configured `automember-synth-template` value the `member` synthesis is disabled.


## Testing

The module was tested thoroughly using **valgrind** to ensure there are no memory leaks in its operation.

