package com.cloudera.sa.cat.ldapjdbcclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LdapsJdbcClientTest {
  @TempDir Path temporaryDirectory;

  @Test
  void ownerPrivateCiNegativeProof() {
    assertTrue(false, "deliberate fail-closed routing proof");
  }

  @Test
  void loadsOnlyAnExplicitReadableConfiguration() throws IOException {
    Path file = temporaryDirectory.resolve("impala.properties");
    Files.writeString(
        file,
        "connection.auth.mode=BROWSER_SSO\n"
            + "connection.url="
            + urlFor(LdapsJdbcClient.AuthMode.BROWSER_SSO)
            + "\n"
            + "jdbc.driver.class.name="
            + FakeDriver.class.getName()
            + "\nconnection.query=SELECT 1\n");

    Properties loaded = LdapsJdbcClient.loadConfiguration(file);

    assertEquals("BROWSER_SSO", loaded.getProperty(LdapsJdbcClient.AUTH_MODE_PROPERTY));
    assertThrows(
        IOException.class,
        () -> LdapsJdbcClient.loadConfiguration(temporaryDirectory.resolve("missing")));
    assertThrows(IOException.class, () -> LdapsJdbcClient.loadConfiguration(null));
  }

  @Test
  void rejectsIncompleteConfigurationAndCommandLine() throws IOException {
    Path file = temporaryDirectory.resolve("incomplete.properties");
    Files.writeString(file, "connection.auth.mode=JWT\n");
    assertThrows(IllegalArgumentException.class, () -> LdapsJdbcClient.loadConfiguration(file));
    Properties unknown = configuration(LdapsJdbcClient.AuthMode.BROWSER_SSO);
    unknown.setProperty("connection.password", "must-not-be-stored-here");
    assertThrows(
        IllegalArgumentException.class,
        () ->
            LdapsJdbcClient.run(
                unknown, System.out, ignored -> null, (url, properties) -> queryConnection()));
    assertThrows(IllegalArgumentException.class, () -> LdapsJdbcClient.main(null));
    assertThrows(IllegalArgumentException.class, () -> LdapsJdbcClient.main(new String[0]));
  }

  @Test
  void suppliesEveryAuthenticationSecretOutsideTheUrlAndOutput() throws Exception {
    Map<String, String> environment =
        Map.of(
            LdapsJdbcClient.USERNAME_ENV, "alice",
            LdapsJdbcClient.PASSWORD_ENV, "ldap secret",
            LdapsJdbcClient.JWT_ENV, "jwt-secret",
            LdapsJdbcClient.OAUTH_TOKEN_ENV, "oauth-secret");
    Map<LdapsJdbcClient.AuthMode, Map<String, String>> expected =
        Map.of(
            LdapsJdbcClient.AuthMode.LDAP, Map.of("UID", "alice", "PWD", "ldap secret"),
            LdapsJdbcClient.AuthMode.JWT, Map.of("JWTString", "jwt-secret"),
            LdapsJdbcClient.AuthMode.OAUTH_TOKEN,
                Map.of("Auth_AccessToken", "oauth-secret"),
            LdapsJdbcClient.AuthMode.BROWSER_SSO, Map.of(),
            LdapsJdbcClient.AuthMode.KERBEROS, Map.of());

    for (LdapsJdbcClient.AuthMode mode : LdapsJdbcClient.AuthMode.values()) {
      Properties configuration = configuration(mode);
      AtomicReference<String> receivedUrl = new AtomicReference<>();
      AtomicReference<Properties> receivedProperties = new AtomicReference<>();
      ByteArrayOutputStream bytes = new ByteArrayOutputStream();

      LdapsJdbcClient.run(
          configuration,
          new PrintStream(bytes, true, StandardCharsets.UTF_8),
          environment::get,
          (url, properties) -> {
            receivedUrl.set(url);
            Properties copy = new Properties();
            copy.putAll(properties);
            receivedProperties.set(copy);
            return queryConnection("first-row", "second-row");
          });

      assertEquals(expected.get(mode), receivedProperties.get());
      assertEquals(urlFor(mode), receivedUrl.get());
      String output = bytes.toString(StandardCharsets.UTF_8);
      assertTrue(output.contains("first-row"));
      assertTrue(output.contains("second-row"));
      assertFalse(output.contains("secret"));
      assertFalse(receivedUrl.get().contains("secret"));
    }
  }

  @Test
  void passesOptionalTruststorePasswordAsADriverProperty() throws Exception {
    Properties configuration = configuration(LdapsJdbcClient.AuthMode.BROWSER_SSO);
    AtomicReference<Properties> received = new AtomicReference<>();

    LdapsJdbcClient.run(
        configuration,
        System.out,
        name ->
            LdapsJdbcClient.TRUSTSTORE_PASSWORD_ENV.equals(name) ? "truststore-secret" : null,
        (url, properties) -> {
          received.set(properties);
          return queryConnection();
        });

    assertEquals("truststore-secret", received.get().getProperty("SSLTrustStorePwd"));
  }

  @Test
  void rejectsUnsafeOrIncorrectConnectionUrls() {
    List<String> unsafe =
        List.of(
            "jdbc:hive2://host/default;AuthMech=14;SSL=1;TransportMode=http;httpPath=x",
            "jdbc:impala:///default;AuthMech=14;SSL=1;TransportMode=http;httpPath=x",
            "jdbc:impala://user:pass@host/default;AuthMech=14;SSL=1;TransportMode=http;httpPath=x",
            "jdbc:impala://host/default;AuthMech=14;TransportMode=http;httpPath=x",
            "jdbc:impala://host/default;AuthMech=3;SSL=1;TransportMode=http;httpPath=x",
            "jdbc:impala://host/default;AuthMech=14;SSL=1;httpPath=x",
            "jdbc:impala://host/default;AuthMech=14;SSL=1;TransportMode=http",
            "jdbc:impala://host/default;AuthMech=11;SSL=1;TransportMode=http;httpPath=x",
            "jdbc:impala://host/default;AuthMech=14;SSL=1;TransportMode=http;httpPath=x;JWTString=secret",
            "jdbc:impala://host/default;AuthMech=14;AuthMech=14;SSL=1;TransportMode=http;httpPath=x",
            "jdbc:impala://host/default;AuthMech=14;SSL=1;TransportMode=http;broken");

    for (String url : unsafe) {
      assertThrows(
          IllegalArgumentException.class,
          () -> LdapsJdbcClient.validateUrl(url, LdapsJdbcClient.AuthMode.JWT),
          url);
    }
  }

  @Test
  void rejectsMissingSecretsAndUnknownAuthenticationModes() {
    Properties ldap = configuration(LdapsJdbcClient.AuthMode.LDAP);
    assertThrows(
        IllegalArgumentException.class,
        () -> LdapsJdbcClient.run(ldap, System.out, ignored -> null, (url, properties) -> null));
    Properties jwt = configuration(LdapsJdbcClient.AuthMode.JWT);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            LdapsJdbcClient.run(
                jwt, System.out, ignored -> "has whitespace", (url, properties) -> null));
    assertThrows(
        IllegalArgumentException.class,
        () -> LdapsJdbcClient.AuthMode.parse("unsupported"));
  }

  private static Properties configuration(LdapsJdbcClient.AuthMode mode) {
    Properties properties = new Properties();
    properties.setProperty(LdapsJdbcClient.CONNECTION_URL_PROPERTY, urlFor(mode));
    properties.setProperty(
        LdapsJdbcClient.JDBC_DRIVER_NAME_PROPERTY, FakeDriver.class.getName());
    properties.setProperty(LdapsJdbcClient.CONNECTION_QUERY, "SELECT value FROM sample");
    properties.setProperty(LdapsJdbcClient.AUTH_MODE_PROPERTY, mode.name());
    return properties;
  }

  private static String urlFor(LdapsJdbcClient.AuthMode mode) {
    String base = "jdbc:impala://impala.example.com:28000/default;AuthMech=";
    return switch (mode) {
      case LDAP -> base + "3;SSL=1";
      case JWT -> base + "14;SSL=1;TransportMode=http;httpPath=cliservice";
      case OAUTH_TOKEN ->
          base + "11;Auth_Flow=0;SSL=1;TransportMode=http;httpPath=cliservice";
      case BROWSER_SSO -> base + "12;SSL=1;TransportMode=http;httpPath=cliservice";
      case KERBEROS -> base + "1;SSL=1";
    };
  }

  private static Connection queryConnection(String... rows) {
    Statement statement =
        proxy(
            Statement.class,
            (methodName, arguments) ->
                "executeQuery".equals(methodName) ? resultSet(rows) : defaultValue(methodName));
    return proxy(
        Connection.class,
        (methodName, arguments) ->
            "createStatement".equals(methodName) ? statement : defaultValue(methodName));
  }

  private static ResultSet resultSet(String[] rows) {
    AtomicInteger index = new AtomicInteger(-1);
    return proxy(
        ResultSet.class,
        (methodName, arguments) -> {
          if ("next".equals(methodName)) {
            return index.incrementAndGet() < rows.length;
          }
          if ("getString".equals(methodName)) {
            return rows[index.get()];
          }
          return defaultValue(methodName);
        });
  }

  private static Object defaultValue(String methodName) {
    return switch (methodName) {
      case "isClosed", "isWrapperFor", "wasNull" -> false;
      default -> null;
    };
  }

  private static <T> T proxy(Class<T> type, Invocation invocation) {
    List<Class<?>> interfaces = new ArrayList<>();
    interfaces.add(type);
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            interfaces.toArray(Class<?>[]::new),
            (proxy, method, arguments) -> invocation.invoke(method.getName(), arguments)));
  }

  @FunctionalInterface
  private interface Invocation {
    Object invoke(String methodName, Object[] arguments) throws Throwable;
  }

  static final class FakeDriver {
    private FakeDriver() {}
  }
}
