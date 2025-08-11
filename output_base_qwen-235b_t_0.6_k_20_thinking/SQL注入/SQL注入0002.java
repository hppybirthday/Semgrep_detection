import java.sql.*;
import java.util.*;
import java.util.function.*;

public class ChatApp {
    static Connection conn;

    static {
        try {
            conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
            Statement stmt = conn.createStatement();
            stmt.execute("CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
            stmt.execute("CREATE TABLE messages (id INT PRIMARY KEY, username VARCHAR(50), message TEXT)");
            stmt.execute("INSERT INTO users VALUES (1, 'admin', 'admin123')");
        } catch (SQLException e) { e.printStackTrace(); }
    }

    static Optional<Map<String, String>> login(String username, String password) {
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                return Optional.of(new HashMap<>());
            }
        } catch (SQLException e) { e.printStackTrace(); }
        return Optional.empty();
    }

    static void sendMessage(String username, String message) {
        String query = "INSERT INTO messages (username, message) VALUES ('" + username + "', '" + message + "')";
        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(query);
        } catch (SQLException e) { e.printStackTrace(); }
    }

    static List<Map<String, String>> getMessages() {
        String query = "SELECT * FROM messages";
        List<Map<String, String>> messages = new ArrayList<>();
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            while (rs.next()) {
                messages.add(new HashMap<>());
            }
        } catch (SQLException e) { e.printStackTrace(); }
        return messages;
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Username:");
        String user = scanner.nextLine();
        System.out.println("Password:");
        String pass = scanner.nextLine();
        
        if (login(user, pass).isPresent()) {
            System.out.println("Logged in! Type message:");
            String msg = scanner.nextLine();
            sendMessage(user, msg);
            System.out.println("Messages:");
            getMessages().forEach(m -> System.out.println(m.get("username") + ": " + m.get("message")));
        } else {
            System.out.println("Login failed");
        }
    }
}