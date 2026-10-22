package com.sla;

import com.sla.dsa.SelfBalancingSearchTree;
import com.sla.model.LogRecord;
import com.sla.model.Role;
import com.sla.model.User;
import com.sla.service.AccessLogParser;
import com.sla.service.BlacklistManager;
import com.sla.service.UserAccessControl;
import com.sla.service.UserAuthService;
import com.sla.util.PasswordHasher;
import com.sla.util.SimpleXorCipher;
import com.sla.util.UserQueryLogger;
import java.io.ByteArrayInputStream;
import java.io.PrintStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

/** Dependency-free test runner: compile with the sources and run {@code java com.sla.SlaTests}. */
public class SlaTests {
    private static int passed = 0;
    private static final List<String> failures = new ArrayList<>();

    interface Check {
        void run() throws Exception;
    }

    static void test(String name, Check check) {
        try {
            check.run();
            passed++;
            System.out.println("PASS  " + name);
        } catch (Throwable t) {
            failures.add(name + ": " + t);
            System.out.println("FAIL  " + name + " -> " + t);
        }
    }

    static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    static void assertEquals(Object expected, Object actual, String message) {
        if (!expected.equals(actual)) {
            throw new AssertionError(message + " expected=" + expected + " actual=" + actual);
        }
    }

    static User login(String usersFile, String username, String password) {
        Scanner in = new Scanner(new ByteArrayInputStream((username + "\n" + password + "\n").repeat(3).getBytes()));
        PrintStream original = System.out;
        System.setOut(new PrintStream(new ByteArrayOutputStream()));
        try {
            return new UserAuthService(in, usersFile).login();
        } finally {
            System.setOut(original);
        }
    }

    public static void main(String[] args) throws Exception {
        Path tmp = Files.createTempDirectory("sla-tests");

        test("password hash verifies and uses random salt", () -> {
            String h1 = PasswordHasher.hash("s3cret");
            String h2 = PasswordHasher.hash("s3cret");
            assertTrue(PasswordHasher.verify("s3cret", h1), "correct password");
            assertTrue(!PasswordHasher.verify("wrong", h1), "wrong password");
            assertTrue(!h1.equals(h2), "salts differ");
            assertTrue(!h1.contains("s3cret"), "hash does not contain password");
        });

        test("plaintext stored password is never accepted", () -> {
            assertTrue(!PasswordHasher.verify("adminpass", "adminpass"), "plaintext rejected");
            assertTrue(!PasswordHasher.verify("x", "pbkdf2$bad"), "malformed hash rejected");
        });

        test("login succeeds with hashed users file and fails otherwise", () -> {
            Path users = tmp.resolve("users.csv");
            Files.writeString(users, "username,password,role,userId\n"
                + "alice," + PasswordHasher.hash("pw-alice") + ",ADMIN,A1\n"
                + "mallory,plain-text-password,ADMIN,M1\n");
            User ok = login(users.toString(), "alice", "pw-alice");
            assertTrue(ok != null && ok.role == Role.ADMIN && ok.userId.equals("A1"), "alice logs in");
            assertTrue(login(users.toString(), "alice", "nope") == null, "wrong password");
            assertTrue(login(users.toString(), "ghost", "x") == null, "unknown user");
            assertTrue(login(users.toString(), "mallory", "plain-text-password") == null, "plaintext entry is skipped");
        });

        test("shipped users.csv contains no plaintext passwords and demo login works", () -> {
            for (String line : Files.readAllLines(Path.of("users.csv")).subList(1, 4)) {
                assertTrue(line.split(",", 4)[1].startsWith("pbkdf2$"), "hashed: " + line.split(",")[0]);
            }
            assertTrue(login("users.csv", "admin", "adminpass") != null, "documented demo login");
        });

        test("query logger prevents log forging via newlines", () -> {
            Path log = tmp.resolve("query.log");
            new UserQueryLogger(log.toString()).log(new User("u", "U1", Role.AUDITOR),
                "legit\n2030-01-01 | UserID: ADM001 | Query: forged");
            List<String> lines = Files.readAllLines(log);
            assertEquals(1, lines.size(), "single log line");
        });

        test("XOR cipher round-trips", () -> {
            String enc = SimpleXorCipher.encrypt("10.0.0.1", "key");
            assertTrue(!enc.equals("10.0.0.1"), "changed");
            assertEquals("10.0.0.1", SimpleXorCipher.decrypt(enc, "key"), "round trip");
        });

        test("blacklist persists and reloads", () -> {
            Path file = tmp.resolve("blacklist.txt");
            BlacklistManager m = new BlacklistManager(file.toString(), "k");
            m.add("1.2.3.4");
            m.add("5.6.7.8");
            m.saveBlacklist();
            BlacklistManager reloaded = new BlacklistManager(file.toString(), "k");
            assertTrue(reloaded.isBlacklisted("1.2.3.4") && reloaded.isBlacklisted("5.6.7.8"), "reloaded");
            assertTrue(!reloaded.isBlacklisted("9.9.9.9"), "unknown ip");
            assertEquals("1.2.3", BlacklistManager.getIpPrefix("1.2.3.4"), "prefix");
        });

        test("red-black tree stays valid and ordered under random insert/delete", () -> {
            SelfBalancingSearchTree<Integer> tree = new SelfBalancingSearchTree<>();
            Random rnd = new Random(42);
            List<Integer> keys = new ArrayList<>();
            for (int i = 0; i < 500; i++) {
                int k = rnd.nextInt(10_000);
                if (!keys.contains(k)) {
                    keys.add(k);
                    tree.insert(k);
                }
            }
            assertTrue(tree.validateTree(), "valid after inserts");
            List<Integer> sorted = new ArrayList<>(keys);
            sorted.sort(null);
            assertEquals(sorted, tree.inOrderTraversal(), "in-order is sorted");
            for (int i = 0; i < 200; i++) {
                assertTrue(tree.delete(keys.get(i)), "delete existing");
            }
            assertTrue(tree.validateTree(), "valid after deletes");
            assertEquals(keys.size() - 200, tree.size(), "size");
        });

        test("red-black tree range, min/max, predecessor/successor", () -> {
            SelfBalancingSearchTree<Integer> tree = new SelfBalancingSearchTree<>();
            for (int k : new int[] {50, 20, 70, 10, 30, 60, 80}) {
                tree.insert(k);
            }
            assertEquals(Arrays.asList(20, 30, 50, 60), tree.rangeQuery(15, 65), "range");
            assertEquals(10, tree.findMinimum(), "min");
            assertEquals(80, tree.findMaximum(), "max");
            assertEquals(30, tree.findPredecessor(50), "predecessor");
            assertEquals(60, tree.findSuccessor(50), "successor");
        });

        test("log parser reads valid lines and skips malformed ones", () -> {
            Path log = tmp.resolve("access.log");
            Files.writeString(log,
                "2024-05-01T10:15:30,10.0.0.5,bob,GET,/index.html,200,ok\n"
                + "not a log line\n"
                + "2024-05-01T10:15:31,10.0.0.6,-,POST,/login,401,bad password\n");
            PrintStream err = System.err;
            System.setErr(new PrintStream(new ByteArrayOutputStream()));
            List<LogRecord> records;
            try {
                records = new AccessLogParser().parseLogs(log.toString());
            } finally {
                System.setErr(err);
            }
            assertEquals(2, records.size(), "two valid records");
            assertEquals(401, records.get(1).httpStatusCode, "status parsed");
        });

        test("auditor sees redacted IPs, investigator sees full IPs", () -> {
            UserAccessControl auditor = new UserAccessControl(new User("a", "A", Role.AUDITOR));
            UserAccessControl investigator = new UserAccessControl(new User("i", "I", Role.INVESTIGATOR));
            assertEquals("10.0.0.XXX", auditor.redactIPAddress("10.0.0.5"), "redacted");
            assertEquals("10.0.0.5", investigator.redactIPAddress("10.0.0.5"), "full");
        });

        System.out.println();
        System.out.println(passed + " passed, " + failures.size() + " failed");
        if (!failures.isEmpty()) {
            failures.forEach(f -> System.out.println("  - " + f));
            System.exit(1);
        }
    }
}
