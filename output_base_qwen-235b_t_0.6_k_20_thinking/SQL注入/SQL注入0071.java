import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.sql.*;

public class GameLogin {
    private static Connection conn;

    public static void main(String[] args) {
        try {
            // 初始化内存数据库
            conn = DriverManager.getConnection("jdbc:sqlite::memory:");
            Statement stmt = conn.createStatement();
            stmt.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
            // 插入测试数据
            stmt.execute("INSERT INTO users (username,password) VALUES ('admin','secret123')");
            
            // 创建登录界面
            JFrame frame = new JFrame("Game Login");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(300, 150);
            frame.setLayout(new GridLayout(3, 2));

            JTextField userField = new JTextField();
            JPasswordField passField = new JPasswordField();
            
            frame.add(new JLabel("Username:"));
            frame.add(userField);
            frame.add(new JLabel("Password:"));
            frame.add(passField);
            
            JButton loginBtn = new JButton("Login");
            loginBtn.addActionListener(e -> {
                String username = userField.getText();
                String password = new String(passField.getPassword());
                
                try {
                    // 存在漏洞的SQL构造方式
                    Statement s = conn.createStatement();
                    String query = "SELECT * FROM users WHERE username='" + username + 
                                  "' AND password='" + password + "'";
                    System.out.println("Executing query: " + query); // 模拟日志记录
                    ResultSet rs = s.executeQuery(query);
                    
                    if (rs.next()) {
                        JOptionPane.showMessageDialog(frame, "Login successful!");
                    } else {
                        JOptionPane.showMessageDialog(frame, "Invalid credentials");
                    }
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            });
            
            frame.add(loginBtn);
            frame.setVisible(true);
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}