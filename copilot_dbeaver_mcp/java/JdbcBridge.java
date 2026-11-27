import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Persistent JDBC worker with:
 * - In-memory DBeaver credentials-config.json decryption (passwords never leave JVM memory)
 * - Automatic SSH tunnel port forwarding via DBeaver's bundled SSHJ jars
 * - Dynamic database/catalog/schema switching per query
 * - Wire-protocol single-statement enforcement, READ ONLY transaction lock, timeouts, and atomic dry-run/rollback
 */
public class JdbcBridge {

    private static final PrintStream PROTOCOL_OUT = System.out;
    private static final List<String> LOADED_DRIVERS = new ArrayList<>();
    private static URLClassLoader PLUGIN_LOADER = null;
    private static final Pattern MULTI_QUERY_PATTERN = Pattern.compile(
            "(?i)(allowMultiQueries|allowMultiStatements)\\s*=\\s*(true|1|yes)");

    // DBeaver standard local credentials-config.json AES-128-CBC key
    private static final byte[] DBEAVER_LOCAL_KEY = new byte[] {
        (byte) 0xba, (byte) 0xbb, (byte) 0x4a, (byte) 0x9f,
        (byte) 0x77, (byte) 0x4a, (byte) 0xb8, (byte) 0x53,
        (byte) 0xc9, (byte) 0x6c, (byte) 0x2d, (byte) 0x65,
        (byte) 0x3d, (byte) 0xfe, (byte) 0x54, (byte) 0x4a
    };

    private static final Map<String, ActiveSshTunnel> SSH_TUNNELS = new ConcurrentHashMap<>();

    private static final class ActiveSshTunnel {
        final Object sshClient;
        final ServerSocket serverSocket;
        final int localPort;

        ActiveSshTunnel(Object sshClient, ServerSocket serverSocket, int localPort) {
            this.sshClient = sshClient;
            this.serverSocket = serverSocket;
            this.localPort = localPort;
        }

        boolean isAlive() {
            try {
                if (serverSocket.isClosed()) return false;
                Method isConn = sshClient.getClass().getMethod("isConnected");
                Method isAuth = sshClient.getClass().getMethod("isAuthenticated");
                return Boolean.TRUE.equals(isConn.invoke(sshClient))
                        && Boolean.TRUE.equals(isAuth.invoke(sshClient));
            } catch (Throwable t) {
                return false;
            }
        }

        void closeQuietly() {
            try {
                serverSocket.close();
            } catch (Throwable ignored) {
            }
            if (sshClient instanceof Closeable c) {
                try {
                    c.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    public static final class DriverShim implements Driver {
        private final Driver delegate;

        public DriverShim(Driver delegate) {
            this.delegate = delegate;
        }

        @Override
        public Connection connect(String u, Properties p) throws SQLException {
            return delegate.connect(u, p);
        }

        @Override
        public boolean acceptsURL(String u) throws SQLException {
            return delegate.acceptsURL(u);
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String u, Properties p) throws SQLException {
            return delegate.getPropertyInfo(u, p);
        }

        @Override
        public int getMajorVersion() {
            return delegate.getMajorVersion();
        }

        @Override
        public int getMinorVersion() {
            return delegate.getMinorVersion();
        }

        @Override
        public boolean jdbcCompliant() {
            return delegate.jdbcCompliant();
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            return delegate.getParentLogger();
        }
    }

    public static void main(String[] args) throws Exception {
        System.setOut(new PrintStream(OutputStream.nullOutputStream(), true, StandardCharsets.UTF_8));
        Runtime.getRuntime().addShutdownHook(new Thread(JdbcBridge::closeAllTunnels));

        List<URL> jarUrls = new ArrayList<>();
        for (String arg : args) {
            collectJars(new File(arg), jarUrls);
        }
        if (!jarUrls.isEmpty()) {
            PLUGIN_LOADER = new URLClassLoader(jarUrls.toArray(new URL[0]), JdbcBridge.class.getClassLoader());
            ServiceLoader<Driver> drivers = ServiceLoader.load(Driver.class, PLUGIN_LOADER);
            Set<String> seen = new HashSet<>();
            for (Driver d : drivers) {
                String cls = d.getClass().getName();
                if (seen.add(cls)) {
                    DriverManager.registerDriver(new DriverShim(d));
                    LOADED_DRIVERS.add(cls);
                }
            }
            String[] knownClasses = new String[] {
                "org.mariadb.jdbc.Driver",
                "com.mysql.cj.jdbc.Driver",
                "oracle.jdbc.OracleDriver",
                "org.postgresql.Driver",
                "com.huawei.gauss200.jdbc.Driver",
                "com.microsoft.sqlserver.jdbc.SQLServerDriver",
                "org.sqlite.JDBC",
                "com.clickhouse.jdbc.ClickHouseDriver",
                "dm.jdbc.driver.DmDriver",
                "com.kingbase8.Driver",
                "com.oceanbase.jdbc.Driver",
                "org.h2.Driver"
            };
            for (String cls : knownClasses) {
                if (!seen.contains(cls)) {
                    try {
                        Class<?> c = Class.forName(cls, true, PLUGIN_LOADER);
                        if (Driver.class.isAssignableFrom(c)) {
                            Driver d = (Driver) c.getDeclaredConstructor().newInstance();
                            DriverManager.registerDriver(new DriverShim(d));
                            seen.add(cls);
                            LOADED_DRIVERS.add(cls);
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }

        startIdlePoolReaper();

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            if ("EXIT".equals(line)) {
                break;
            }
            handleRequest(line);
        }
        closeAllTunnels();
    }

    private static void closeAllTunnels() {
        for (IdleConn ic : CONN_POOL.values()) {
            ic.closePhysical();
        }
        CONN_POOL.clear();
        for (ActiveSshTunnel t : SSH_TUNNELS.values()) {
            t.closeQuietly();
        }
        SSH_TUNNELS.clear();
    }

    private static void collectJars(File file, List<URL> urls) {
        if (file == null || !file.exists()) {
            return;
        }
        if (file.isFile() && file.getName().toLowerCase().endsWith(".jar")) {
            try {
                urls.add(file.toURI().toURL());
            } catch (Exception ignored) {
            }
            return;
        }
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    collectJars(child, urls);
                }
            }
        }
    }

    private static String b64Decode(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8);
    }

    // -------------------- Credential Cache & Idle-TTL Connection Pool --------------------

    private static final long IDLE_TTL_MS = 180_000L; // 3 minutes idle auto-eviction
    private static final Map<String, CredCacheEntry> CRED_CACHE = new ConcurrentHashMap<>();
    private static final Map<String, IdleConn> CONN_POOL = new ConcurrentHashMap<>();

    private record CredCacheEntry(long mtime, long size, Map<String, Object> parsed) {}

    private static final class IdleConn {
        final Connection conn;
        volatile long lastReturnedAtMs;

        IdleConn(Connection conn) {
            this.conn = conn;
            this.lastReturnedAtMs = System.currentTimeMillis();
        }

        void closePhysical() {
            try {
                conn.close();
            } catch (Throwable ignored) {
            }
        }
    }

    private static final class PooledConn implements AutoCloseable {
        final String poolKey;
        final Connection conn;
        boolean broken = false;

        PooledConn(String poolKey, Connection conn) {
            this.poolKey = poolKey;
            this.conn = conn;
        }

        void markBroken() {
            this.broken = true;
        }

        @Override
        public void close() {
            try {
                if (!conn.isClosed()) {
                    try {
                        conn.rollback();
                    } catch (SQLException ignored) {
                    }
                    try {
                        conn.setReadOnly(false);
                    } catch (SQLException ignored) {
                    }
                }
            } catch (SQLException e) {
                broken = true;
            }
            if (broken || poolKey == null) {
                try {
                    conn.close();
                } catch (Throwable ignored) {
                }
                return;
            }
            try {
                if (conn.isClosed()) {
                    return;
                }
            } catch (SQLException e) {
                try {
                    conn.close();
                } catch (Throwable ignored) {
                }
                return;
            }
            IdleConn prev = CONN_POOL.put(poolKey, new IdleConn(conn));
            if (prev != null && prev.conn != conn) {
                prev.closePhysical();
            }
        }
    }

    private static void startIdlePoolReaper() {
        Thread reaper = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(30_000L);
                    long now = System.currentTimeMillis();
                    for (Map.Entry<String, IdleConn> entry : CONN_POOL.entrySet()) {
                        IdleConn ic = entry.getValue();
                        if (now - ic.lastReturnedAtMs > IDLE_TTL_MS) {
                            if (CONN_POOL.remove(entry.getKey(), ic)) {
                                ic.closePhysical();
                            }
                        }
                    }
                } catch (InterruptedException ie) {
                    break;
                } catch (Throwable ignored) {
                }
            }
        }, "copilot-dbeaver-pool-reaper");
        reaper.setDaemon(true);
        reaper.start();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> decryptDbeaverCredentials(String credFilePath) throws Exception {
        File f = new File(credFilePath);
        if (!f.isFile()) {
            return Map.of();
        }
        long mtime = f.lastModified();
        long size = f.length();
        CredCacheEntry cached = CRED_CACHE.get(credFilePath);
        if (cached != null && cached.mtime() == mtime && cached.size() == size) {
            return cached.parsed();
        }
        byte[] raw = Files.readAllBytes(f.toPath());
        if (raw.length <= 16) {
            return Map.of();
        }
        byte[] iv = Arrays.copyOfRange(raw, 0, 16);
        byte[] cipherBytes = Arrays.copyOfRange(raw, 16, raw.length);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(DBEAVER_LOCAL_KEY, "AES"),
                new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherBytes);
        String jsonText = new String(plain, StandardCharsets.UTF_8).trim();
        Object parsed = new MiniJsonParser(jsonText).parseValue();
        if (parsed instanceof Map<?, ?> m) {
            Map<String, Object> map = (Map<String, Object>) m;
            CRED_CACHE.put(credFilePath, new CredCacheEntry(mtime, size, map));
            return map;
        }
        return Map.of();
    }

    private static int ensureSshTunnel(
            String connId,
            String bastionHost,
            int bastionPort,
            String remoteHost,
            int remotePort,
            String authType,
            String sshUser,
            String sshPass,
            String privateKeyPath) throws Exception {
        String key = connId + "|" + bastionHost + ":" + bastionPort + "->" + remoteHost + ":" + remotePort;
        ActiveSshTunnel existing = SSH_TUNNELS.get(key);
        if (existing != null && existing.isAlive()) {
            return existing.localPort;
        }
        if (existing != null) {
            existing.closeQuietly();
            SSH_TUNNELS.remove(key);
        }
        if (PLUGIN_LOADER == null) {
            throw new IllegalStateException("SSHJ plugin loader not initialized.");
        }

        ClassLoader prevCl = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(PLUGIN_LOADER);
        try {
            Class<?> sshClientCls = Class.forName("net.schmizz.sshj.SSHClient", true, PLUGIN_LOADER);
            Class<?> hostVerifierIntf = Class.forName(
                    "net.schmizz.sshj.transport.verification.HostKeyVerifier", true, PLUGIN_LOADER);
            Class<?> promiscuousCls = Class.forName(
                    "net.schmizz.sshj.transport.verification.PromiscuousVerifier", true, PLUGIN_LOADER);
            Class<?> paramsCls = Class.forName(
                    "net.schmizz.sshj.connection.channel.direct.Parameters", true, PLUGIN_LOADER);

            Object ssh = sshClientCls.getDeclaredConstructor().newInstance();
            Object verifier = promiscuousCls.getDeclaredConstructor().newInstance();
            sshClientCls.getMethod("addHostKeyVerifier", hostVerifierIntf).invoke(ssh, verifier);
            sshClientCls.getMethod("connect", String.class, int.class).invoke(ssh, bastionHost, bastionPort);

            if ("PUBLIC_KEY".equalsIgnoreCase(authType) && privateKeyPath != null && !privateKeyPath.isEmpty()) {
                if (sshPass != null && !sshPass.isEmpty()) {
                    Object kp = sshClientCls.getMethod("loadKeys", String.class, String.class)
                            .invoke(ssh, privateKeyPath, sshPass);
                    Class<?> kpArrCls = Class.forName(
                            "[Lnet.schmizz.sshj.userauth.keyprovider.KeyProvider;", true, PLUGIN_LOADER);
                    Object arr = java.lang.reflect.Array.newInstance(kpArrCls.getComponentType(), 1);
                    java.lang.reflect.Array.set(arr, 0, kp);
                    sshClientCls.getMethod("authPublickey", String.class, kpArrCls).invoke(ssh, sshUser, arr);
                } else {
                    sshClientCls.getMethod("authPublickey", String.class, String[].class)
                            .invoke(ssh, sshUser, (Object) new String[] {privateKeyPath});
                }
            } else {
                sshClientCls.getMethod("authPassword", String.class, String.class)
                        .invoke(ssh, sshUser, sshPass != null ? sshPass : "");
            }

            ServerSocket ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress("127.0.0.1", 0));
            int localPort = ss.getLocalPort();

            Constructor<?> paramsCtor = paramsCls.getConstructor(String.class, int.class, String.class, int.class);
            Object params = paramsCtor.newInstance("127.0.0.1", localPort, remoteHost, remotePort);
            Object forwarder = sshClientCls
                    .getMethod("newLocalPortForwarder", paramsCls, ServerSocket.class)
                    .invoke(ssh, params, ss);
            Method listenMethod = forwarder.getClass().getMethod("listen");

            Thread tunnelThread = new Thread(() -> {
                try {
                    listenMethod.invoke(forwarder);
                } catch (Throwable ignored) {
                }
            }, "copilot-dbeaver-ssh-" + connId);
            tunnelThread.setDaemon(true);
            tunnelThread.start();

            ActiveSshTunnel active = new ActiveSshTunnel(ssh, ss, localPort);
            SSH_TUNNELS.put(key, active);
            return localPort;
        } finally {
            Thread.currentThread().setContextClassLoader(prevCl);
        }
    }

    private static String sanitizeJdbcUrl(String rawUrl, String targetDb) {
        String safe = MULTI_QUERY_PATTERN.matcher(rawUrl).replaceAll("$1=false");
        String lower = safe.toLowerCase();

        // For PostgreSQL / GaussDB, if a specific database name is requested, rewrite URL database path if needed
        if (targetDb != null && !targetDb.isEmpty() && lower.startsWith("jdbc:postgresql://")) {
            int slashIdx = safe.indexOf('/', "jdbc:postgresql://".length());
            if (slashIdx > 0) {
                int qIdx = safe.indexOf('?', slashIdx);
                String prefix = safe.substring(0, slashIdx + 1);
                String suffix = qIdx >= 0 ? safe.substring(qIdx) : "";
                safe = prefix + targetDb + suffix;
            }
        }

        if ((lower.startsWith("jdbc:mysql:") || lower.startsWith("jdbc:mariadb:"))
                && !safe.toLowerCase().contains("allowmultiqueries=")) {
            safe += (safe.contains("?") ? "&" : "?") + "allowMultiQueries=false";
        }
        return safe;
    }

    @SuppressWarnings("unchecked")
    private static PooledConn openResolvedConnection(
            String rawJdbcUrl,
            String userSpec,
            String passSpec,
            String targetDb,
            String extraPropsText,
            int loginTimeoutSec) throws Exception {
        String effectiveUrl = rawJdbcUrl;
        String resolvedUser = userSpec;
        String resolvedPass = passSpec;

        if (userSpec != null && userSpec.startsWith("@DBEAVER:")) {
            // Format: @DBEAVER:<connId>|<credFilePath>
            String payload = userSpec.substring("@DBEAVER:".length());
            int sep = payload.indexOf('|');
            String connId = sep >= 0 ? payload.substring(0, sep) : payload;
            String credFile = sep >= 0 ? payload.substring(sep + 1) : "";

            Map<String, Object> allCreds = decryptDbeaverCredentials(credFile);
            Map<String, Object> entry = (Map<String, Object>) allCreds.getOrDefault(connId, Map.of());
            Map<String, Object> dbAuth = (Map<String, Object>) entry.getOrDefault("#connection", Map.of());
            resolvedUser = strOrEmpty(dbAuth.get("user"));
            resolvedPass = strOrEmpty(dbAuth.get("password"));

            if (passSpec != null && passSpec.startsWith("@SSH:")) {
                // Format: @SSH:bastionHost|bastionPort|remoteHost|remotePort|authType|privateKeyPath
                String[] sp = passSpec.substring("@SSH:".length()).split("\\|", -1);
                if (sp.length >= 6) {
                    String bastionHost = sp[0];
                    int bastionPort = parseInt(sp[1], 22);
                    String remoteHost = sp[2];
                    int remotePort = parseInt(sp[3], 3306);
                    String authType = sp[4];
                    String privKey = sp[5];

                    Map<String, Object> sshAuth = (Map<String, Object>) entry.getOrDefault("ssh_tunnel", Map.of());
                    String sshUser = strOrEmpty(sshAuth.get("user"));
                    String sshPass = strOrEmpty(sshAuth.get("password"));

                    int localPort = ensureSshTunnel(
                            connId, bastionHost, bastionPort, remoteHost, remotePort,
                            authType, sshUser, sshPass, privKey);
                    effectiveUrl = effectiveUrl.replace(
                            remoteHost + ":" + remotePort, "127.0.0.1:" + localPort);
                }
            }
        }

        DriverManager.setLoginTimeout(Math.max(3, loginTimeoutSec));
        String safeUrl = sanitizeJdbcUrl(effectiveUrl, targetDb);
        Properties props = new Properties();
        if (extraPropsText != null && !extraPropsText.isEmpty()) {
            for (String kv : extraPropsText.split("\n")) {
                int eq = kv.indexOf('=');
                if (eq > 0) {
                    String k = kv.substring(0, eq).trim();
                    String v = kv.substring(eq + 1).trim();
                    if (!k.equalsIgnoreCase("allowMultiQueries") && !k.equalsIgnoreCase("allowMultiStatements")) {
                        props.setProperty(k, v);
                    }
                }
            }
        }
        if (resolvedUser != null && !resolvedUser.isEmpty()) {
            props.setProperty("user", resolvedUser);
        }
        if (resolvedPass != null && !resolvedPass.isEmpty()) {
            props.setProperty("password", resolvedPass);
        }

        // Don't pool URLs carrying one-shot H2 INIT=... scripts
        boolean cacheable = !safeUrl.toUpperCase().contains(";INIT=");
        String poolKey = cacheable ? (safeUrl + "|" + resolvedUser + "|" + (targetDb != null ? targetDb : "")) : null;
        if (poolKey != null) {
            IdleConn idle = CONN_POOL.remove(poolKey);
            if (idle != null) {
                try {
                    if (!idle.conn.isClosed() && idle.conn.isValid(2)) {
                        idle.conn.setAutoCommit(false);
                        applyTargetDatabase(idle.conn, safeUrl, targetDb);
                        return new PooledConn(poolKey, idle.conn);
                    }
                } catch (Throwable ignored) {
                }
                idle.closePhysical();
            }
        }

        Connection conn = DriverManager.getConnection(safeUrl, props);
        conn.setAutoCommit(false);
        applyTargetDatabase(conn, safeUrl, targetDb);
        return new PooledConn(poolKey, conn);
    }

    private static void applyTargetDatabase(Connection conn, String jdbcUrl, String targetDb) throws SQLException {
        if (targetDb == null || targetDb.isEmpty()) {
            return;
        }
        if (!targetDb.matches("^[A-Za-z0-9_$-]+$")) {
            throw new SQLException("Invalid database/schema identifier: " + targetDb);
        }
        String lower = jdbcUrl.toLowerCase();
        if (lower.startsWith("jdbc:mysql:") || lower.startsWith("jdbc:mariadb:") || lower.startsWith("jdbc:sqlserver:")) {
            conn.setCatalog(targetDb);
        } else if (lower.startsWith("jdbc:oracle:") || lower.startsWith("jdbc:dm:")) {
            try (Statement st = conn.createStatement()) {
                st.execute("ALTER SESSION SET CURRENT_SCHEMA = \"" + targetDb.toUpperCase() + "\"");
            }
        } else if (lower.startsWith("jdbc:h2:") || lower.startsWith("jdbc:kingbase8:")) {
            try {
                conn.setSchema(targetDb);
            } catch (SQLException ignored) {
            }
        }
    }

    private static String strOrEmpty(Object o) {
        return o == null ? "" : o.toString();
    }

    private static void enforceSessionReadOnly(Connection conn, String jdbcUrl) {
        try {
            conn.setReadOnly(true);
        } catch (SQLException ignored) {
        }
        String lower = jdbcUrl.toLowerCase();
        if (lower.startsWith("jdbc:mysql:") || lower.startsWith("jdbc:mariadb:")
                || lower.startsWith("jdbc:postgresql:") || lower.startsWith("jdbc:kingbase8:")) {
            try (Statement st = conn.createStatement()) {
                st.execute("SET SESSION TRANSACTION READ ONLY");
            } catch (SQLException ignored) {
            }
        } else if (lower.startsWith("jdbc:oracle:") || lower.startsWith("jdbc:dm:")) {
            try (Statement st = conn.createStatement()) {
                st.execute("SET TRANSACTION READ ONLY");
            } catch (SQLException ignored) {
            }
        } else if (lower.startsWith("jdbc:sqlite:")) {
            try (Statement st = conn.createStatement()) {
                st.execute("PRAGMA query_only = ON");
            } catch (SQLException ignored) {
            }
        }
    }

    private static void handleRequest(String line) {
        // Format: REQ|id|mode|b64Url|b64User|b64Pass|timeoutSec|maxRows|dryRun|expectedRows|b64Arg1|b64Arg2|b64TargetDb|b64Props
        String[] parts = line.split("\\|", -1);
        if (parts.length < 12 || !"REQ".equals(parts[0])) {
            emitError("unknown", "Malformed request frame", null, -1);
            return;
        }
        String reqId = parts[1];
        String mode = parts[2];
        String jdbcUrl = b64Decode(parts[3]);
        String user = b64Decode(parts[4]);
        String pass = b64Decode(parts[5]);
        int timeoutSec = parseInt(parts[6], 8);
        int maxRows = parseInt(parts[7], 100);
        boolean dryRun = Boolean.parseBoolean(parts[8]);
        int expectedRows = parseInt(parts[9], -1);
        String arg1 = b64Decode(parts[10]);
        String arg2 = b64Decode(parts[11]);
        String targetDb = parts.length > 12 ? b64Decode(parts[12]) : "";
        String extraProps = parts.length > 13 ? b64Decode(parts[13]) : "";

        try {
            switch (mode) {
                case "PING" -> emitPing(reqId);
                case "LIST_DBS" -> handleListDbs(reqId, jdbcUrl, user, pass, targetDb, extraProps, timeoutSec);
                case "SCHEMA" -> handleSchema(reqId, jdbcUrl, user, pass, targetDb, extraProps, timeoutSec, maxRows, arg1, arg2);
                case "BULK_SCHEMA" -> handleBulkSchema(reqId, jdbcUrl, user, pass, targetDb, extraProps, timeoutSec, maxRows, arg1, arg2);
                case "QUERY" -> handleQuery(reqId, jdbcUrl, user, pass, targetDb, extraProps, timeoutSec, maxRows, arg1);
                case "REMEDIATE" -> handleRemediate(
                        reqId, jdbcUrl, user, pass, targetDb, extraProps, timeoutSec, maxRows, dryRun, expectedRows, arg1, arg2);
                case "SEED" -> handleSeed(
                        reqId, jdbcUrl, user, pass, targetDb, extraProps, timeoutSec, maxRows, dryRun, arg1, arg2);
                case "EXEC_BATCH" -> handleExecBatch(
                        reqId, jdbcUrl, user, pass, targetDb, extraProps, timeoutSec, dryRun, arg1);
                default -> emitError(reqId, "Unsupported mode: " + mode, null, -1);
            }
        } catch (SQLException sqle) {
            emitError(reqId, sqle.getMessage(), sqle.getSQLState(), sqle.getErrorCode());
        } catch (Throwable t) {
            emitError(reqId, t.getClass().getSimpleName() + ": " + t.getMessage(), null, -1);
        }
    }

    private static int parseInt(String s, int fallback) {
        try {
            return Integer.parseInt(s);
        } catch (Exception e) {
            return fallback;
        }
    }

    private static void emitPing(String reqId) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"id\":").append(jsonStr(reqId))
          .append(",\"ok\":true,\"drivers\":[");
        for (int i = 0; i < LOADED_DRIVERS.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(jsonStr(LOADED_DRIVERS.get(i)));
        }
        sb.append("]}");
        emitLine(sb.toString());
    }

    private static void handleListDbs(
            String reqId, String jdbcUrl, String user, String pass,
            String targetDb, String extraProps, int timeoutSec) throws Exception {
        try (PooledConn pc = openResolvedConnection(jdbcUrl, user, pass, targetDb, extraProps, timeoutSec)) {
            Connection conn = pc.conn;
            conn.setAutoCommit(false);
            enforceSessionReadOnly(conn, jdbcUrl);
            try {
                DatabaseMetaData meta = conn.getMetaData();
                List<String> dbs = new ArrayList<>();
                try (ResultSet rs = meta.getCatalogs()) {
                    while (rs.next()) {
                        String c = rs.getString(1);
                        if (c != null && !c.isEmpty()) dbs.add(c);
                    }
                } catch (SQLException ignored) {
                }
                if (dbs.isEmpty()) {
                    try (ResultSet rs = meta.getSchemas()) {
                        while (rs.next()) {
                            String s = rs.getString(1);
                            if (s != null && !s.isEmpty()) dbs.add(s);
                        }
                    } catch (SQLException ignored) {
                    }
                }
                StringBuilder sb = new StringBuilder();
                sb.append("{\"id\":").append(jsonStr(reqId))
                  .append(",\"ok\":true,\"productName\":").append(jsonStr(meta.getDatabaseProductName()))
                  .append(",\"currentDatabase\":").append(jsonStr(conn.getCatalog()))
                  .append(",\"databases\":[");
                for (int i = 0; i < dbs.size(); i++) {
                    if (i > 0) sb.append(',');
                    sb.append(jsonStr(dbs.get(i)));
                }
                sb.append("]}");
                emitLine(sb.toString());
            } finally {
                try {
                    conn.rollback();
                } catch (SQLException ignored) {
                }
            }
        }
    }

    private static void handleSchema(
            String reqId, String jdbcUrl, String user, String pass, String targetDb, String extraProps,
            int timeoutSec, int maxRows, String schemaFilter, String tableTarget) throws Exception {
        try (PooledConn pc = openResolvedConnection(jdbcUrl, user, pass, targetDb, extraProps, timeoutSec)) {
            Connection conn = pc.conn;
            conn.setAutoCommit(false);
            enforceSessionReadOnly(conn, jdbcUrl);
            try {
                DatabaseMetaData meta = conn.getMetaData();
                String effectiveFilter = (schemaFilter != null && !schemaFilter.isEmpty())
                        ? schemaFilter
                        : (targetDb != null && !targetDb.isEmpty() ? targetDb : conn.getCatalog());
                String catalog = (effectiveFilter != null && !effectiveFilter.isEmpty()) ? effectiveFilter : null;
                String schemaPattern = null;
                if (jdbcUrl.toLowerCase().startsWith("jdbc:oracle:") && effectiveFilter != null) {
                    catalog = null;
                    schemaPattern = effectiveFilter.toUpperCase();
                }

                // Collect available databases if no database was selected yet
                List<String> availableDbs = new ArrayList<>();
                if (catalog == null && schemaPattern == null) {
                    try (ResultSet rs = meta.getCatalogs()) {
                        while (rs.next()) {
                            String c = rs.getString(1);
                            if (c != null && !c.isEmpty()) availableDbs.add(c);
                        }
                    } catch (SQLException ignored) {
                    }
                }

                boolean exactTable = tableTarget != null && !tableTarget.isEmpty() && !tableTarget.contains("%");
                StringBuilder sb = new StringBuilder();
                sb.append("{\"id\":").append(jsonStr(reqId))
                  .append(",\"ok\":true,\"productName\":").append(jsonStr(meta.getDatabaseProductName()))
                  .append(",\"productVersion\":").append(jsonStr(meta.getDatabaseProductVersion()))
                  .append(",\"activeDatabase\":").append(jsonStr(conn.getCatalog()));

                if (!availableDbs.isEmpty()) {
                    sb.append(",\"availableDatabases\":[");
                    for (int i = 0; i < availableDbs.size(); i++) {
                        if (i > 0) sb.append(',');
                        sb.append(jsonStr(availableDbs.get(i)));
                    }
                    sb.append(']');
                }

                if (!exactTable) {
                    String pattern = (tableTarget == null || tableTarget.isEmpty()) ? "%" : tableTarget;
                    sb.append(",\"tables\":[");
                    int count = 0;
                    if (catalog != null || schemaPattern != null || availableDbs.isEmpty()) {
                        try (ResultSet rs = meta.getTables(catalog, schemaPattern, pattern, new String[] {"TABLE", "VIEW"})) {
                            while (rs.next() && count < maxRows) {
                                if (count > 0) sb.append(',');
                                sb.append("{\"catalog\":").append(jsonStr(rs.getString("TABLE_CAT")))
                                  .append(",\"schema\":").append(jsonStr(rs.getString("TABLE_SCHEM")))
                                  .append(",\"name\":").append(jsonStr(rs.getString("TABLE_NAME")))
                                  .append(",\"type\":").append(jsonStr(rs.getString("TABLE_TYPE")))
                                  .append(",\"remarks\":").append(jsonStr(rs.getString("REMARKS")))
                                  .append('}');
                                count++;
                            }
                        }
                    }
                    sb.append("]}");
                } else {
                    sb.append(",\"table\":").append(jsonStr(tableTarget));
                    Set<String> pks = new HashSet<>();
                    try (ResultSet rs = meta.getPrimaryKeys(catalog, schemaPattern, tableTarget)) {
                        while (rs.next()) {
                            pks.add(rs.getString("COLUMN_NAME"));
                        }
                    }
                    sb.append(",\"primaryKeys\":[");
                    int idx = 0;
                    for (String pk : pks) {
                        if (idx++ > 0) sb.append(',');
                        sb.append(jsonStr(pk));
                    }
                    sb.append(']');

                    sb.append(",\"columns\":[");
                    int colCount = 0;
                    try (ResultSet rs = meta.getColumns(catalog, schemaPattern, tableTarget, "%")) {
                        while (rs.next()) {
                            if (colCount++ > 0) sb.append(',');
                            String colName = rs.getString("COLUMN_NAME");
                            sb.append("{\"name\":").append(jsonStr(colName))
                              .append(",\"type\":").append(jsonStr(rs.getString("TYPE_NAME")))
                              .append(",\"size\":").append(rs.getInt("COLUMN_SIZE"))
                              .append(",\"nullable\":").append(rs.getInt("NULLABLE") != DatabaseMetaData.columnNoNulls)
                              .append(",\"defaultValue\":").append(jsonStr(rs.getString("COLUMN_DEF")))
                              .append(",\"primaryKey\":").append(pks.contains(colName))
                              .append(",\"remarks\":").append(jsonStr(rs.getString("REMARKS")))
                              .append('}');
                        }
                    }
                    sb.append(']');

                    sb.append(",\"foreignKeys\":[");
                    int fkCount = 0;
                    try (ResultSet rs = meta.getImportedKeys(catalog, schemaPattern, tableTarget)) {
                        while (rs.next()) {
                            if (fkCount++ > 0) sb.append(',');
                            sb.append("{\"fkColumn\":").append(jsonStr(rs.getString("FKCOLUMN_NAME")))
                              .append(",\"pkTable\":").append(jsonStr(rs.getString("PKTABLE_NAME")))
                              .append(",\"pkColumn\":").append(jsonStr(rs.getString("PKCOLUMN_NAME")))
                              .append(",\"fkName\":").append(jsonStr(rs.getString("FK_NAME")))
                              .append('}');
                        }
                    } catch (SQLException ignored) {
                    }
                    sb.append(']');

                    String ddl = null;
                    String lower = jdbcUrl.toLowerCase();
                    if ((lower.startsWith("jdbc:mysql:") || lower.startsWith("jdbc:mariadb:"))
                            && tableTarget.matches("^[A-Za-z0-9_]+$")) {
                        try (Statement st = conn.createStatement();
                             ResultSet rs = st.executeQuery("SHOW CREATE TABLE `" + tableTarget + "`")) {
                            if (rs.next() && rs.getMetaData().getColumnCount() >= 2) {
                                ddl = rs.getString(2);
                            }
                        } catch (SQLException ignored) {
                        }
                    }
                    sb.append(",\"ddl\":").append(jsonStr(ddl)).append('}');
                }
                emitLine(sb.toString());
            } finally {
                try {
                    conn.rollback();
                } catch (SQLException ignored) {
                }
            }
        }
    }

    private static void handleQuery(
            String reqId, String jdbcUrl, String user, String pass, String targetDb, String extraProps,
            int timeoutSec, int maxRows, String sql) throws Exception {
        int cap = Math.max(1, Math.min(maxRows, 500));
        try (PooledConn pc = openResolvedConnection(jdbcUrl, user, pass, targetDb, extraProps, timeoutSec)) {
            Connection conn = pc.conn;
            conn.setAutoCommit(false);
            enforceSessionReadOnly(conn, jdbcUrl);
            try (Statement st = conn.createStatement()) {
                st.setQueryTimeout(Math.max(1, timeoutSec));
                st.setMaxRows(cap + 1);
                long startNs = System.nanoTime();
                try (ResultSet rs = st.executeQuery(sql)) {
                    long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;
                    QuerySnapshot snap = readResultSet(rs, cap);
                    StringBuilder sb = new StringBuilder();
                    sb.append("{\"id\":").append(jsonStr(reqId))
                      .append(",\"ok\":true,\"elapsedMs\":").append(elapsedMs)
                      .append(",\"activeDatabase\":").append(jsonStr(conn.getCatalog()))
                      .append(",\"truncated\":").append(snap.truncated)
                      .append(",\"rowCount\":").append(snap.rows.size())
                      .append(",\"columns\":").append(snap.columnsJson())
                      .append(",\"rows\":").append(snap.rowsJson())
                      .append('}');
                    emitLine(sb.toString());
                }
            } finally {
                try {
                    conn.rollback();
                } catch (SQLException ignored) {
                }
            }
        }
    }

    private static void handleRemediate(
            String reqId, String jdbcUrl, String user, String pass, String targetDb, String extraProps,
            int timeoutSec, int maxWriteRows, boolean dryRun, int expectedRows,
            String selectSql, String dmlSql) throws Exception {
        int safeCap = Math.max(1, Math.min(maxWriteRows, 100));
        try (PooledConn pc = openResolvedConnection(jdbcUrl, user, pass, targetDb, extraProps, timeoutSec)) {
            Connection conn = pc.conn;
            conn.setAutoCommit(false);
            try {
                conn.setReadOnly(false);
            } catch (SQLException ignored) {
            }
            boolean committed = false;
            try (Statement st = conn.createStatement()) {
                st.setQueryTimeout(Math.max(1, timeoutSec));
                st.setMaxRows(safeCap + 1);

                QuerySnapshot beforeSnap;
                try (ResultSet rs = st.executeQuery(selectSql)) {
                    beforeSnap = readResultSet(rs, safeCap);
                }
                if (beforeSnap.truncated) {
                    conn.rollback();
                    emitError(reqId,
                            "Safety circuit breaker triggered: WHERE clause matched more than max_write_rows (" + safeCap + "). Transaction rolled back.",
                            "45000", -1);
                    return;
                }

                st.setMaxRows(0);
                int affected = st.executeUpdate(dmlSql);
                if (affected > safeCap) {
                    conn.rollback();
                    emitError(reqId,
                            "Safety circuit breaker triggered: DML affected " + affected + " rows > max_write_rows (" + safeCap + "). Transaction rolled back.",
                            "45000", -1);
                    return;
                }
                if (!dryRun && expectedRows >= 0 && affected != expectedRows) {
                    conn.rollback();
                    emitError(reqId,
                            "Row-count lock mismatch: expected " + expectedRows + " affected rows, but DML affected " + affected + ". Transaction rolled back.",
                            "45000", -1);
                    return;
                }

                st.setMaxRows(safeCap + 1);
                QuerySnapshot afterSnap;
                try (ResultSet rs = st.executeQuery(selectSql)) {
                    afterSnap = readResultSet(rs, safeCap);
                }

                if (dryRun) {
                    conn.rollback();
                } else {
                    conn.commit();
                    committed = true;
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"id\":").append(jsonStr(reqId))
                  .append(",\"ok\":true,\"dryRun\":").append(dryRun)
                  .append(",\"committed\":").append(committed)
                  .append(",\"affectedRows\":").append(affected)
                  .append(",\"columns\":").append(beforeSnap.columnsJson())
                  .append(",\"beforeRows\":").append(beforeSnap.rowsJson())
                  .append(",\"afterRows\":").append(afterSnap.rowsJson())
                  .append('}');
                emitLine(sb.toString());
            } catch (SQLException e) {
                try {
                    conn.rollback();
                } catch (SQLException ignored) {
                }
                throw e;
            } finally {
                if (!committed) {
                    try {
                        conn.rollback();
                    } catch (SQLException ignored) {
                    }
                }
            }
        }
    }

    private static void handleBulkSchema(
            String reqId, String jdbcUrl, String user, String pass, String targetDb, String extraProps,
            int timeoutSec, int maxTables, String schemaFilter, String tablePattern) throws Exception {
        int cap = Math.max(1, Math.min(maxTables, 500));
        try (PooledConn pc = openResolvedConnection(jdbcUrl, user, pass, targetDb, extraProps, timeoutSec)) {
            Connection conn = pc.conn;
            conn.setAutoCommit(false);
            enforceSessionReadOnly(conn, jdbcUrl);
            try {
                DatabaseMetaData meta = conn.getMetaData();
                String effectiveFilter = (schemaFilter != null && !schemaFilter.isEmpty())
                        ? schemaFilter
                        : (targetDb != null && !targetDb.isEmpty() ? targetDb : conn.getCatalog());
                String catalog = (effectiveFilter != null && !effectiveFilter.isEmpty()) ? effectiveFilter : null;
                String schemaPat = null;
                if ((jdbcUrl.toLowerCase().startsWith("jdbc:oracle:") || jdbcUrl.toLowerCase().startsWith("jdbc:dm:"))
                        && effectiveFilter != null) {
                    catalog = null;
                    schemaPat = effectiveFilter.toUpperCase();
                }
                String pat = (tablePattern == null || tablePattern.isEmpty()) ? "%" : tablePattern;

                Map<String, List<Map<String, Object>>> tableCols = new LinkedHashMap<>();
                try (ResultSet rs = meta.getTables(catalog, schemaPat, pat, new String[] {"TABLE"})) {
                    while (rs.next() && tableCols.size() < cap) {
                        tableCols.put(rs.getString("TABLE_NAME"), new ArrayList<>());
                    }
                }

                // Single JDBC metadata sweep for all columns across matching tables!
                try (ResultSet rs = meta.getColumns(catalog, schemaPat, pat, "%")) {
                    while (rs.next()) {
                        String tName = rs.getString("TABLE_NAME");
                        List<Map<String, Object>> cols = tableCols.get(tName);
                        if (cols != null) {
                            Map<String, Object> c = new LinkedHashMap<>();
                            c.put("name", rs.getString("COLUMN_NAME"));
                            c.put("type", rs.getString("TYPE_NAME"));
                            c.put("size", rs.getInt("COLUMN_SIZE"));
                            c.put("nullable", rs.getInt("NULLABLE") != DatabaseMetaData.columnNoNulls);
                            c.put("defaultValue", rs.getString("COLUMN_DEF"));
                            cols.add(c);
                        }
                    }
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"id\":").append(jsonStr(reqId))
                  .append(",\"ok\":true,\"productName\":").append(jsonStr(meta.getDatabaseProductName()))
                  .append(",\"activeDatabase\":").append(jsonStr(conn.getCatalog()))
                  .append(",\"tables\":{");
                int tIdx = 0;
                for (Map.Entry<String, List<Map<String, Object>>> entry : tableCols.entrySet()) {
                    if (tIdx++ > 0) sb.append(',');
                    String tName = entry.getKey();
                    List<String> pks = new ArrayList<>();
                    try (ResultSet pkRs = meta.getPrimaryKeys(catalog, schemaPat, tName)) {
                        while (pkRs.next()) {
                            pks.add(pkRs.getString("COLUMN_NAME"));
                        }
                    } catch (SQLException ignored) {
                    }
                    sb.append(jsonStr(tName)).append(":{\"primaryKeys\":[");
                    for (int i = 0; i < pks.size(); i++) {
                        if (i > 0) sb.append(',');
                        sb.append(jsonStr(pks.get(i)));
                    }
                    sb.append("],\"columns\":[");
                    List<Map<String, Object>> cols = entry.getValue();
                    for (int i = 0; i < cols.size(); i++) {
                        if (i > 0) sb.append(',');
                        Map<String, Object> c = cols.get(i);
                        sb.append("{\"name\":").append(jsonStr((String) c.get("name")))
                          .append(",\"type\":").append(jsonStr((String) c.get("type")))
                          .append(",\"size\":").append(c.get("size"))
                          .append(",\"nullable\":").append(c.get("nullable"))
                          .append(",\"defaultValue\":").append(jsonStr((String) c.get("defaultValue")))
                          .append('}');
                    }
                    sb.append("]}");
                }
                sb.append("}}");
                emitLine(sb.toString());
            } finally {
                try {
                    conn.rollback();
                } catch (SQLException ignored) {
                }
            }
        }
    }

    private static void handleExecBatch(
            String reqId, String jdbcUrl, String user, String pass, String targetDb, String extraProps,
            int timeoutSec, boolean dryRun, String statementsJson) throws Exception {
        Object parsed = new MiniJsonParser(statementsJson).parseValue();
        if (!(parsed instanceof List<?> stmtList) || stmtList.isEmpty()) {
            emitError(reqId, "EXEC_BATCH requires a non-empty JSON array of DML statements.", "45000", -1);
            return;
        }
        try (PooledConn pc = openResolvedConnection(jdbcUrl, user, pass, targetDb, extraProps, timeoutSec)) {
            Connection conn = pc.conn;
            conn.setAutoCommit(false);
            try {
                conn.setReadOnly(false);
            } catch (SQLException ignored) {
            }
            boolean committed = false;
            try (Statement st = conn.createStatement()) {
                st.setQueryTimeout(Math.max(1, timeoutSec));
                int totalAffected = 0;
                for (Object item : stmtList) {
                    totalAffected += st.executeUpdate(strOrEmpty(item));
                }
                if (dryRun) {
                    conn.rollback();
                } else {
                    conn.commit();
                    committed = true;
                }
                emitLine("{\"id\":" + jsonStr(reqId)
                        + ",\"ok\":true,\"dryRun\":" + dryRun
                        + ",\"committed\":" + committed
                        + ",\"statementCount\":" + stmtList.size()
                        + ",\"affectedRows\":" + totalAffected + "}");
            } catch (SQLException e) {
                pc.markBroken();
                try {
                    conn.rollback();
                } catch (SQLException ignored) {
                }
                throw e;
            } finally {
                if (!committed) {
                    try {
                        conn.rollback();
                    } catch (SQLException ignored) {
                    }
                }
            }
        }
    }

    private static void handleSeed(
            String reqId, String jdbcUrl, String user, String pass, String targetDb, String extraProps,
            int timeoutSec, int maxSeedRows, boolean dryRun, String checkAndVerifySelectSql, String batchInsertsJson)
            throws Exception {
        int safeCap = Math.max(1, Math.min(maxSeedRows, 200));
        Object parsed = new MiniJsonParser(batchInsertsJson).parseValue();
        if (!(parsed instanceof List<?> insertList) || insertList.isEmpty()) {
            emitError(reqId, "SEED requires a non-empty JSON array of INSERT statements.", "45000", -1);
            return;
        }
        if (insertList.size() > safeCap) {
            emitError(reqId, "SEED batch size (" + insertList.size() + ") exceeds max_seed_rows (" + safeCap + ").", "45000", -1);
            return;
        }

        try (PooledConn pc = openResolvedConnection(jdbcUrl, user, pass, targetDb, extraProps, timeoutSec)) {
            Connection conn = pc.conn;
            conn.setAutoCommit(false);
            try {
                conn.setReadOnly(false);
            } catch (SQLException ignored) {
            }
            boolean committed = false;
            try (Statement st = conn.createStatement()) {
                st.setQueryTimeout(Math.max(1, timeoutSec));
                st.setMaxRows(safeCap + 1);

                // Collision pre-check: ensure none of the target seed primary keys already exist!
                try (ResultSet rs = st.executeQuery(checkAndVerifySelectSql)) {
                    QuerySnapshot existing = readResultSet(rs, safeCap);
                    if (!existing.rows.isEmpty()) {
                        conn.rollback();
                        emitError(reqId,
                                "Seed collision detected: " + existing.rows.size()
                                        + " row(s) already exist matching target keys. Aborted to protect existing data.",
                                "23000", -1);
                        return;
                    }
                }

                st.setMaxRows(0);
                int totalInserted = 0;
                for (Object item : insertList) {
                    String insSql = strOrEmpty(item);
                    totalInserted += st.executeUpdate(insSql);
                }

                st.setMaxRows(safeCap + 1);
                QuerySnapshot afterSnap;
                try (ResultSet rs = st.executeQuery(checkAndVerifySelectSql)) {
                    afterSnap = readResultSet(rs, safeCap);
                }

                if (dryRun) {
                    conn.rollback();
                } else {
                    conn.commit();
                    committed = true;
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"id\":").append(jsonStr(reqId))
                  .append(",\"ok\":true,\"dryRun\":").append(dryRun)
                  .append(",\"committed\":").append(committed)
                  .append(",\"insertedRows\":").append(totalInserted)
                  .append(",\"columns\":").append(afterSnap.columnsJson())
                  .append(",\"afterRows\":").append(afterSnap.rowsJson())
                  .append('}');
                emitLine(sb.toString());
            } catch (SQLException e) {
                try {
                    conn.rollback();
                } catch (SQLException ignored) {
                }
                throw e;
            } finally {
                if (!committed) {
                    try {
                        conn.rollback();
                    } catch (SQLException ignored) {
                    }
                }
            }
        }
    }

    private static final class QuerySnapshot {
        final List<Map<String, String>> columns = new ArrayList<>();
        final List<List<Object>> rows = new ArrayList<>();
        boolean truncated = false;

        String columnsJson() {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < columns.size(); i++) {
                if (i > 0) sb.append(',');
                Map<String, String> c = columns.get(i);
                sb.append("{\"name\":").append(jsonStr(c.get("name")))
                  .append(",\"type\":").append(jsonStr(c.get("type"))).append('}');
            }
            sb.append(']');
            return sb.toString();
        }

        String rowsJson() {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < rows.size(); i++) {
                if (i > 0) sb.append(',');
                List<Object> row = rows.get(i);
                sb.append('[');
                for (int j = 0; j < row.size(); j++) {
                    if (j > 0) sb.append(',');
                    sb.append(jsonVal(row.get(j)));
                }
                sb.append(']');
            }
            sb.append(']');
            return sb.toString();
        }
    }

    private static QuerySnapshot readResultSet(ResultSet rs, int cap) throws SQLException {
        QuerySnapshot snap = new QuerySnapshot();
        ResultSetMetaData md = rs.getMetaData();
        int colCount = md.getColumnCount();
        for (int i = 1; i <= colCount; i++) {
            Map<String, String> col = new LinkedHashMap<>();
            String label = md.getColumnLabel(i);
            if (label == null || label.isEmpty()) {
                label = md.getColumnName(i);
            }
            col.put("name", label);
            col.put("type", md.getColumnTypeName(i));
            snap.columns.add(col);
        }
        while (rs.next()) {
            if (snap.rows.size() >= cap) {
                snap.truncated = true;
                break;
            }
            List<Object> row = new ArrayList<>(colCount);
            for (int i = 1; i <= colCount; i++) {
                Object val = rs.getObject(i);
                if (val == null) {
                    row.add(null);
                } else if (val instanceof Number || val instanceof Boolean) {
                    row.add(val);
                } else if (val instanceof byte[] bytes) {
                    row.add("[BLOB " + bytes.length + " bytes]");
                } else {
                    String s = rs.getString(i);
                    if (s != null && s.length() > 4000) {
                        s = s.substring(0, 4000) + "...[TRUNCATED len=" + s.length() + "]";
                    }
                    row.add(s);
                }
            }
            snap.rows.add(row);
        }
        return snap;
    }

    private static void emitError(String reqId, String message, String sqlState, int errorCode) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"id\":").append(jsonStr(reqId))
          .append(",\"ok\":false,\"error\":").append(jsonStr(message))
          .append(",\"sqlState\":").append(jsonStr(sqlState))
          .append(",\"errorCode\":").append(errorCode)
          .append('}');
        emitLine(sb.toString());
    }

    private static synchronized void emitLine(String json) {
        PROTOCOL_OUT.println(json);
        PROTOCOL_OUT.flush();
    }

    private static String jsonVal(Object val) {
        if (val == null) return "null";
        if (val instanceof Boolean b) return b.toString();
        if (val instanceof Integer || val instanceof Long || val instanceof Short || val instanceof Byte) {
            return val.toString();
        }
        if (val instanceof Number n) {
            return Double.isFinite(n.doubleValue()) ? val.toString() : jsonStr(val.toString());
        }
        return jsonStr(val.toString());
    }

    private static String jsonStr(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder(s.length() + 8);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /** Minimal RFC 8259 JSON parser for in-memory DBeaver credentials-config.json parsing. */
    private static final class MiniJsonParser {
        private final String s;
        private int pos = 0;

        MiniJsonParser(String s) {
            this.s = s;
            if (!s.isEmpty() && s.charAt(0) == '\uFEFF') {
                this.pos = 1;
            }
        }

        Object parseValue() {
            skipWs();
            if (pos >= s.length()) return null;
            char c = s.charAt(pos);
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't', 'f' -> parseBoolean();
                case 'n' -> parseNull();
                default -> parseNumber();
            };
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> map = new HashMap<>();
            pos++; // '{'
            skipWs();
            if (pos < s.length() && s.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (pos < s.length()) {
                skipWs();
                String key = parseString();
                skipWs();
                if (pos < s.length() && s.charAt(pos) == ':') pos++;
                Object val = parseValue();
                map.put(key, val);
                skipWs();
                if (pos < s.length() && s.charAt(pos) == ',') {
                    pos++;
                } else if (pos < s.length() && s.charAt(pos) == '}') {
                    pos++;
                    break;
                } else {
                    break;
                }
            }
            return map;
        }

        private List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            pos++; // '['
            skipWs();
            if (pos < s.length() && s.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (pos < s.length()) {
                list.add(parseValue());
                skipWs();
                if (pos < s.length() && s.charAt(pos) == ',') {
                    pos++;
                } else if (pos < s.length() && s.charAt(pos) == ']') {
                    pos++;
                    break;
                } else {
                    break;
                }
            }
            return list;
        }

        private String parseString() {
            if (pos >= s.length() || s.charAt(pos) != '"') return "";
            pos++;
            StringBuilder sb = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == '"') break;
                if (c == '\\' && pos < s.length()) {
                    char esc = s.charAt(pos++);
                    switch (esc) {
                        case '"', '\\', '/' -> sb.append(esc);
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (pos + 4 <= s.length()) {
                                sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                                pos += 4;
                            }
                        }
                        default -> sb.append(esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Boolean parseBoolean() {
            if (s.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            pos += 5;
            return Boolean.FALSE;
        }

        private Object parseNull() {
            pos += 4;
            return null;
        }

        private Number parseNumber() {
            int start = pos;
            while (pos < s.length() && "-+0123456789.eE".indexOf(s.charAt(pos)) >= 0) {
                pos++;
            }
            String num = s.substring(start, pos);
            return num.contains(".") || num.contains("e") || num.contains("E")
                    ? Double.parseDouble(num)
                    : Long.parseLong(num);
        }

        private void skipWs() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
                pos++;
            }
        }
    }
}
