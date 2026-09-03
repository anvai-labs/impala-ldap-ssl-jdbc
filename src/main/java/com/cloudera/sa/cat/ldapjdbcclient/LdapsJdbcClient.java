package com.cloudera.sa.cat.ldapjdbcclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.function.Function;

/** Secure Impala JDBC example supporting passwordless and compatibility authentication modes. */
public final class LdapsJdbcClient {
  static final String CONNECTION_URL_PROPERTY = "connection.url";
  static final String JDBC_DRIVER_NAME_PROPERTY = "jdbc.driver.class.name";
  static final String CONNECTION_QUERY = "connection.query";
  static final String AUTH_MODE_PROPERTY = "connection.auth.mode";

  static final String USERNAME_ENV = "IMPALA_USERNAME";
  static final String PASSWORD_ENV = "IMPALA_PASSWORD";
  static final String JWT_ENV = "IMPALA_JWT";
  static final String OAUTH_TOKEN_ENV = "IMPALA_OAUTH_ACCESS_TOKEN";
  static final String TRUSTSTORE_PASSWORD_ENV = "IMPALA_TRUSTSTORE_PASSWORD";

  private static final Set<String> FORBIDDEN_URL_PROPERTIES =
      Set.of("pwd", "password", "jwtstring", "auth_accesstoken", "ssltruststorepwd");
  private static final Set<String> ALLOWED_CONFIGURATION_PROPERTIES =
      Set.of(
          CONNECTION_URL_PROPERTY,
          JDBC_DRIVER_NAME_PROPERTY,
          CONNECTION_QUERY,
          AUTH_MODE_PROPERTY);

  private LdapsJdbcClient() {}

  static Properties loadConfiguration(Path path) throws IOException {
    if (path == null || !Files.isRegularFile(path) || !Files.isReadable(path)) {
      throw new IOException("Configuration is not a readable regular file: " + path);
    }
    try (InputStream input = Files.newInputStream(path)) {
      Properties properties = new Properties();
      properties.load(input);
      validateConfigurationKeys(properties);
      requireProperty(properties, CONNECTION_URL_PROPERTY);
      requireProperty(properties, JDBC_DRIVER_NAME_PROPERTY);
      requireProperty(properties, CONNECTION_QUERY);
      requireProperty(properties, AUTH_MODE_PROPERTY);
      return properties;
    }
  }

  static void run(Properties configuration, PrintStream output)
      throws ClassNotFoundException, SQLException {
    run(configuration, output, System::getenv, DriverManager::getConnection);
  }

  static void run(
      Properties configuration,
      PrintStream output,
      Function<String, String> environment,
      ConnectionFactory connectionFactory)
      throws ClassNotFoundException, SQLException {
    Objects.requireNonNull(configuration, "configuration");
    Objects.requireNonNull(output, "output");
    Objects.requireNonNull(environment, "environment");
    Objects.requireNonNull(connectionFactory, "connectionFactory");
    validateConfigurationKeys(configuration);

    String url = requireProperty(configuration, CONNECTION_URL_PROPERTY);
    String driverName = requireProperty(configuration, JDBC_DRIVER_NAME_PROPERTY);
    String query = requireProperty(configuration, CONNECTION_QUERY);
    AuthMode authMode = AuthMode.parse(requireProperty(configuration, AUTH_MODE_PROPERTY));
    validateUrl(url, authMode);
    Properties credentials = credentials(authMode, environment);

    String truststorePassword = environment.apply(TRUSTSTORE_PASSWORD_ENV);
    if (truststorePassword != null && !truststorePassword.isBlank()) {
      credentials.setProperty(
          "SSLTrustStorePwd", requireSecret(environment, TRUSTSTORE_PASSWORD_ENV));
    }

    Class.forName(driverName);
    output.println("Cloudera Impala JDBC authentication mode: " + authMode);
    output.println("Running configured query");
    try (Connection connection = connectionFactory.open(url, credentials);
        Statement statement = connection.createStatement();
        ResultSet results = statement.executeQuery(query)) {
      while (results.next()) {
        output.println(results.getString(1));
      }
    }
  }

  static Map<String, String> validateUrl(String url, AuthMode authMode) {
    if (!url.toLowerCase(Locale.ROOT).startsWith("jdbc:impala://")) {
      throw new IllegalArgumentException("connection.url must use the jdbc:impala scheme");
    }
    validateAuthority(url);
    Map<String, String> properties = parseUrlProperties(url);
    for (String forbidden : FORBIDDEN_URL_PROPERTIES) {
      if (properties.containsKey(forbidden)) {
        throw new IllegalArgumentException(
            "Secret property " + forbidden + " must be supplied through the environment");
      }
    }
    requireUrlProperty(properties, "ssl", "1");
    requireUrlProperty(properties, "authmech", authMode.authMech);
    if (authMode.httpRequired) {
      requireUrlProperty(properties, "transportmode", "http");
      requireUrlProperty(properties, "httppath", null);
    }
    if (authMode == AuthMode.OAUTH_TOKEN) {
      requireUrlProperty(properties, "auth_flow", "0");
    }
    return Map.copyOf(properties);
  }

  private static void validateAuthority(String url) {
    int start = "jdbc:impala://".length();
    int slash = url.indexOf('/', start);
    int semicolon = url.indexOf(';', start);
    int end = url.length();
    if (slash >= 0) {
      end = Math.min(end, slash);
    }
    if (semicolon >= 0) {
      end = Math.min(end, semicolon);
    }
    String authority = url.substring(start, end);
    if (authority.isBlank() || authority.contains("@")) {
      throw new IllegalArgumentException(
          "Impala JDBC URL must include a host and must not embed user information");
    }
  }

  private static Map<String, String> parseUrlProperties(String url) {
    Map<String, String> properties = new HashMap<>();
    String[] sections = url.split(";", -1);
    for (int index = 1; index < sections.length; index++) {
      int separator = sections[index].indexOf('=');
      if (separator <= 0 || separator == sections[index].length() - 1) {
        throw new IllegalArgumentException("Malformed Impala JDBC URL property");
      }
      String key = sections[index].substring(0, separator).trim().toLowerCase(Locale.ROOT);
      String value = sections[index].substring(separator + 1).trim();
      if (key.isEmpty() || value.isEmpty()) {
        throw new IllegalArgumentException("Malformed Impala JDBC URL property");
      }
      if (properties.putIfAbsent(key, value) != null) {
        throw new IllegalArgumentException("Duplicate Impala JDBC URL property: " + key);
      }
    }
    return properties;
  }

  private static void requireUrlProperty(
      Map<String, String> properties, String key, String expectedValue) {
    String actualValue = properties.get(key);
    if (actualValue == null
        || (expectedValue != null && !expectedValue.equalsIgnoreCase(actualValue))) {
      String requirement = expectedValue == null ? "a value" : expectedValue;
      throw new IllegalArgumentException(
          "Impala JDBC URL must set " + key + "=" + requirement);
    }
  }

  private static Properties credentials(
      AuthMode authMode, Function<String, String> environment) {
    Properties properties = new Properties();
    switch (authMode) {
      case LDAP -> {
        properties.setProperty("UID", requireSecret(environment, USERNAME_ENV));
        properties.setProperty("PWD", requireSecret(environment, PASSWORD_ENV));
      }
      case JWT -> properties.setProperty("JWTString", requireToken(environment, JWT_ENV));
      case OAUTH_TOKEN ->
          properties.setProperty(
              "Auth_AccessToken", requireToken(environment, OAUTH_TOKEN_ENV));
      case BROWSER_SSO, KERBEROS -> {
        // The driver uses the browser/IdP flow or the process ticket cache respectively.
      }
    }
    return properties;
  }

  private static String requireSecret(
      Function<String, String> environment, String variableName) {
    String value = environment.apply(variableName);
    if (value == null || value.isBlank() || value.chars().anyMatch(Character::isISOControl)) {
      throw new IllegalArgumentException(variableName + " must contain a non-blank value");
    }
    return value;
  }

  private static String requireToken(
      Function<String, String> environment, String variableName) {
    String value = requireSecret(environment, variableName);
    if (value.chars().anyMatch(Character::isWhitespace)) {
      throw new IllegalArgumentException(variableName + " must contain one non-whitespace token");
    }
    return value;
  }

  private static void validateConfigurationKeys(Properties properties) {
    for (String key : properties.stringPropertyNames()) {
      if (!ALLOWED_CONFIGURATION_PROPERTIES.contains(key)) {
        throw new IllegalArgumentException("Unsupported configuration property: " + key);
      }
    }
  }

  private static String requireProperty(Properties properties, String key) {
    String value = properties.getProperty(key);
    if (value == null || value.trim().isEmpty()) {
      throw new IllegalArgumentException("Missing required configuration property: " + key);
    }
    return value.trim();
  }

  public static void main(String[] args) throws IOException, ClassNotFoundException, SQLException {
    if (args == null || args.length != 1) {
      throw new IllegalArgumentException("Usage: <external-configuration.properties>");
    }
    run(loadConfiguration(Path.of(args[0])), System.out);
  }

  enum AuthMode {
    LDAP("3", false),
    JWT("14", true),
    OAUTH_TOKEN("11", true),
    BROWSER_SSO("12", true),
    KERBEROS("1", false);

    private final String authMech;
    private final boolean httpRequired;

    AuthMode(String authMech, boolean httpRequired) {
      this.authMech = authMech;
      this.httpRequired = httpRequired;
    }

    static AuthMode parse(String value) {
      try {
        return valueOf(value.toUpperCase(Locale.ROOT));
      } catch (IllegalArgumentException error) {
        throw new IllegalArgumentException("Unsupported connection.auth.mode: " + value, error);
      }
    }
  }

  @FunctionalInterface
  interface ConnectionFactory {
    Connection open(String url, Properties properties) throws SQLException;
  }
}
