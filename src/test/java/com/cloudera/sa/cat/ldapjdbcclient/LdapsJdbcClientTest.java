package com.cloudera.sa.cat.ldapjdbcclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class LdapsJdbcClientTest {

    @AfterEach
    void clearTrustStoreProperties() {
        System.clearProperty("javax.net.ssl.trustStore");
        System.clearProperty("javax.net.ssl.trustStorePassword");
        FakeDriver.reset();
    }

    @Test
    void rejectsMissingConfigurationResource() {
        IOException error = assertThrows(IOException.class,
                () -> LdapsJdbcClient.loadConfiguration(null));
        assertTrue(error.getMessage().contains("was not found"));
    }

    @Test
    void rejectsBlankRequiredProperty() {
        Properties properties = validProperties();
        properties.setProperty(LdapsJdbcClient.CONNECTION_QUERY, "  ");

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> LdapsJdbcClient.run(properties, System.out));
        assertTrue(error.getMessage().contains(LdapsJdbcClient.CONNECTION_QUERY));
    }

    @Test
    void loadsConfigurationAndRunsQueryWithoutPrintingSecrets() throws Exception {
        Properties expected = validProperties();
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        expected.store(encoded, "test");

        Properties loaded = LdapsJdbcClient.loadConfiguration(
                new ByteArrayInputStream(encoded.toByteArray()));
        ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
        LdapsJdbcClient.run(loaded, new PrintStream(outputBytes, true, "UTF-8"));

        String output = new String(outputBytes.toByteArray(), StandardCharsets.UTF_8);
        assertTrue(output.contains("first-row"));
        assertTrue(output.contains("second-row"));
        assertFalse(output.contains("test-password"));
        assertFalse(output.contains("trust-password"));
        assertEquals("jdbc:fake:impala", FakeDriver.lastUrl);
        assertEquals("test-user", FakeDriver.lastProperties.getProperty("user"));
        assertEquals("test-password", FakeDriver.lastProperties.getProperty("password"));
        assertEquals("select value from sample", FakeDriver.lastQuery);
        assertEquals("/tmp/test-truststore.jks", System.getProperty("javax.net.ssl.trustStore"));
        assertEquals("trust-password", System.getProperty("javax.net.ssl.trustStorePassword"));
    }

    private static Properties validProperties() {
        Properties properties = new Properties();
        properties.setProperty(LdapsJdbcClient.CONNECTION_URL_PROPERTY, "jdbc:fake:impala");
        properties.setProperty(LdapsJdbcClient.JDBC_DRIVER_NAME_PROPERTY, FakeDriver.class.getName());
        properties.setProperty(LdapsJdbcClient.CONNECTION_USERNAME, "test-user");
        properties.setProperty(LdapsJdbcClient.CONNECTION_PASSWORD, "test-password");
        properties.setProperty(LdapsJdbcClient.CONNECTION_QUERY, "select value from sample");
        properties.setProperty(LdapsJdbcClient.CONNECTION_TRUSTSTORE_FILE, "/tmp/test-truststore.jks");
        properties.setProperty(LdapsJdbcClient.CONNECTION_TRUSTSTORE_PASSWORD, "trust-password");
        return properties;
    }

    public static final class FakeDriver implements Driver {
        static String lastUrl;
        static Properties lastProperties;
        static String lastQuery;

        static {
            try {
                DriverManager.registerDriver(new FakeDriver());
            } catch (SQLException error) {
                throw new ExceptionInInitializerError(error);
            }
        }

        static void reset() {
            lastUrl = null;
            lastProperties = null;
            lastQuery = null;
        }

        @Override
        public Connection connect(String url, Properties info) {
            if (!acceptsURL(url)) {
                return null;
            }
            lastUrl = url;
            lastProperties = new Properties();
            lastProperties.putAll(info);
            return proxy(Connection.class, (method, args) -> {
                if (method.getName().equals("createStatement")) {
                    return statement();
                }
                return defaultValue(method.getReturnType());
            });
        }

        @Override
        public boolean acceptsURL(String url) {
            return url != null && url.startsWith("jdbc:fake:");
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
            return new DriverPropertyInfo[0];
        }

        @Override
        public int getMajorVersion() {
            return 1;
        }

        @Override
        public int getMinorVersion() {
            return 0;
        }

        @Override
        public boolean jdbcCompliant() {
            return false;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException();
        }

        private static Statement statement() {
            return proxy(Statement.class, (method, args) -> {
                if (method.getName().equals("executeQuery")) {
                    lastQuery = (String) args[0];
                    return resultSet();
                }
                return defaultValue(method.getReturnType());
            });
        }

        private static ResultSet resultSet() {
            AtomicInteger row = new AtomicInteger(-1);
            String[] values = {"first-row", "second-row"};
            return proxy(ResultSet.class, (method, args) -> {
                if (method.getName().equals("next")) {
                    return row.incrementAndGet() < values.length;
                }
                if (method.getName().equals("getString")) {
                    return values[row.get()];
                }
                return defaultValue(method.getReturnType());
            });
        }

        private static <T> T proxy(Class<T> type, JdbcInvocation invocation) {
            InvocationHandler handler = (Object proxy, Method method, Object[] args) ->
                    invocation.invoke(method, args);
            return type.cast(Proxy.newProxyInstance(
                    type.getClassLoader(), new Class<?>[]{type}, handler));
        }

        private static Object defaultValue(Class<?> type) {
            if (!type.isPrimitive()) {
                return null;
            }
            if (type == boolean.class) {
                return false;
            }
            if (type == char.class) {
                return '\0';
            }
            return 0;
        }

        @FunctionalInterface
        private interface JdbcInvocation {
            Object invoke(Method method, Object[] args) throws Throwable;
        }
    }
}
