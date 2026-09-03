# Secure Impala JDBC

This Java 17 example uses the external Cloudera JDBC Connector for Apache Impala 2.6.38. The
vendor driver is not redistributed through Maven or bundled in this repository; download it from
Cloudera and place it on the runtime classpath.

The historical Java class name is `LdapsJdbcClient`, but the implementation now supports all
current connector authentication boundaries:

| Mode | Connector settings | Secret source |
| --- | --- | --- |
| Browser SSO | `AuthMech=12`, HTTPS, HTTP transport | Browser and configured SAML/OIDC IdP |
| JWT | `AuthMech=14`, HTTPS, HTTP transport | `IMPALA_JWT` |
| OAuth token pass-through | `AuthMech=11`, `Auth_Flow=0`, HTTPS, HTTP transport | `IMPALA_OAUTH_ACCESS_TOKEN` |
| Kerberos | `AuthMech=1`, TLS | Existing ticket cache / JAAS subject |
| LDAP compatibility | `AuthMech=3`, TLS | `IMPALA_USERNAME` and `IMPALA_PASSWORD` |

The current connector documentation is the [2.6.38 installation guide](https://docs.cloudera.com/application-resources/latest/connectors/impala-jdbc/2-6-38/Cloudera-JDBC-Connector-for-Apache-Impala-Install-Guide.pdf).
Cloudera also documents [SAML-backed browser SSO for Impala Virtual Warehouses](https://docs.cloudera.com/data-warehouse/cloud/managing-warehouses/topics/dw-enabling-sso-to-virtual-warehouse.html).

## Security contract

- Every connection must use the `jdbc:impala` scheme and `SSL=1`.
- JWT, OAuth, and browser SSO must use HTTP transport and a configured `httpPath`.
- Passwords, JWTs, OAuth tokens, and truststore passwords are rejected if embedded in the URL.
- Secret values come from environment variables and are passed to the driver as connection
  properties. They are never printed.
- Configuration is loaded only from an explicit readable external file. No runnable credential
  file is packaged in the JAR.
- Example URLs contain only non-secret settings. Copy one outside the repository before use.

For a private truststore password, export `IMPALA_TRUSTSTORE_PASSWORD`; keep the truststore path in
the non-secret JDBC URL using the property supported by the connector.

## Build and run

```bash
./mvnw -B -ntp clean verify
export IMPALA_JWT='<short-lived-token>'
java -cp 'target/impala-ldap-ssl-jdbc-1.0-SNAPSHOT.jar:<path-to-cloudera-driver-jars>/*' \
  com.cloudera.sa.cat.ldapjdbcclient.LdapsJdbcClient \
  /absolute/path/to/jwt.properties
```

CI tests Java 17 and 21, fails when tests are missing, and enforces at least 80% line and 70%
branch coverage. Live connector/cluster verification remains an optional protected-environment lane
because Cloudera distributes the driver separately and a real IdP/Impala endpoint is required.
