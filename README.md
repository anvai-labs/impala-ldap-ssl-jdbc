# impala-ldap-ssl-jdbc

Sample client for Impala LDAP-over-TLS JDBC authentication.

Copy `LdapsJdbcClient.conf.properties`, replace every example value, and point
it at a truststore that you create locally. JKS files are intentionally ignored
and must not be committed. Set `jdbc.driver.class.name` to the vendor-supported
Impala/Hive JDBC driver and supply that driver JAR on the runtime classpath.
The project no longer pins the obsolete CDH 5.3 dependency set.

Build and verify the project with:

```bash
mvn -B -ntp clean verify
```

The build fails when tests are missing and enforces at least 75% line coverage.
CI verifies Java 8, 17, and 21.
