import java.sql.*;
import java.util.Scanner;

public class ChatApp {
    static {
        try {
            Class.forName("org.sqlite.JDBC");
            Connection conn = DriverManager.getConnection("jdbc:sqlite:chat.db");
            Statement stmt = conn.createStatement();
            stmt.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, sender TEXT, content TEXT, receiver TEXT)");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static class Message {
        String sender, content, receiver;
        Message(String s, String c, String r) {
            sender = s; content = c; receiver = r;
        }
    }

    static class MessageDAO {
        void saveMessage(Message msg) {
            try {
                Connection conn = DriverManager.getConnection("jdbc:sqlite:chat.db");
                Statement stmt = conn.createStatement();
                String sql = "INSERT INTO messages (sender, content, receiver) VALUES ('"
                    + msg.sender + "', '" + msg.content + "', '" + msg.receiver + "')";
                stmt.executeUpdate(sql);
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        ResultSet getMessages(String user) {
            try {
                Connection conn = DriverManager.getConnection("jdbc:sqlite:chat.db");
                Statement stmt = conn.createStatement();
                String sql = "SELECT * FROM messages WHERE receiver='" + user + "' ORDER BY id DESC LIMIT 50";
                return stmt.executeQuery(sql);
            } catch (SQLException e) {
                e.printStackTrace();
                return null;
            }
        }
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        MessageDAO dao = new MessageDAO();
        
        System.out.print("Enter username: ");
        String user = sc.nextLine();
        
        System.out.print("Enter message content: ");
        String content = sc.nextLine();
        
        dao.saveMessage(new Message(user, content, "admin"));
        
        System.out.println("\
Last messages for " + user + ":");
        ResultSet rs = dao.getMessages(user);
        try {
            while (rs != null && rs.next()) {
                System.out.println(rs.getString("sender") + ": " + rs.getString("content"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}