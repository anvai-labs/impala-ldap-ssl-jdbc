package com.cloudera.sa.cat.ldapjdbcclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/** Minimal Impala JDBC client configured from a classpath properties file. */
public final class LdapsJdbcClient {

    static final String CONNECTION_URL_PROPERTY = "connection.url";
    static final String JDBC_DRIVER_NAME_PROPERTY = "jdbc.driver.class.name";
    static final String CONNECTION_USERNAME = "connection.username";
    static final String CONNECTION_PASSWORD = "connection.password";
    static final String CONNECTION_QUERY = "connection.query";
    static final String CONNECTION_TRUSTSTORE_FILE = "connection.truststore.jks.file";
    static final String CONNECTION_TRUSTSTORE_PASSWORD = "connection.truststore.jks.password";

    private static final List<String> REQUIRED_PROPERTIES = Arrays.asList(
            CONNECTION_URL_PROPERTY,
            JDBC_DRIVER_NAME_PROPERTY,
            CONNECTION_USERNAME,
            CONNECTION_PASSWORD,
            CONNECTION_QUERY,
            CONNECTION_TRUSTSTORE_FILE,
            CONNECTION_TRUSTSTORE_PASSWORD);

    private LdapsJdbcClient() {
    }

    static Properties loadConfiguration(InputStream input) throws IOException {
        if (input == null) {
            throw new IOException("LdapsJdbcClient.conf.properties was not found on the classpath");
        }

        Properties properties = new Properties();
        try (InputStream configuration = input) {
            properties.load(configuration);
        }
        for (String key : REQUIRED_PROPERTIES) {
            requireProperty(properties, key);
        }
        return properties;
    }

    static void run(Properties properties, PrintStream output)
            throws ClassNotFoundException, SQLException {
        String connectionUrl = requireProperty(properties, CONNECTION_URL_PROPERTY);
        String driverName = requireProperty(properties, JDBC_DRIVER_NAME_PROPERTY);
        String username = requireProperty(properties, CONNECTION_USERNAME);
        String password = requireProperty(properties, CONNECTION_PASSWORD);
        String query = requireProperty(properties, CONNECTION_QUERY);
        String trustStore = requireProperty(properties, CONNECTION_TRUSTSTORE_FILE);
        String trustStorePassword = requireProperty(properties, CONNECTION_TRUSTSTORE_PASSWORD);

        System.setProperty("javax.net.ssl.trustStore", trustStore);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);
        Class.forName(driverName);

        output.println("=============================================");
        output.println("Cloudera Impala LDAP JDBC");
        output.println("Running configured query");

        try (Connection connection = DriverManager.getConnection(connectionUrl, username, password);
             Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery(query)) {
            output.println("== Begin Query Results ======================");
            while (results.next()) {
                output.println(results.getString(1));
            }
            output.println("== End Query Results ========================");
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
        String filename = LdapsJdbcClient.class.getSimpleName() + ".conf.properties";
        InputStream input = LdapsJdbcClient.class.getClassLoader().getResourceAsStream(filename);
        run(loadConfiguration(input), System.out);
    }
}
