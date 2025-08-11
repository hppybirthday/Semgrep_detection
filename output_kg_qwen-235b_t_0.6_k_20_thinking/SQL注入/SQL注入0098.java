package chat;

import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ChatServlet extends HttpServlet {
    private Connection conn;

    public void init() {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/chatdb", "root", "password");
        } catch (Exception e) {
            throw new RuntimeException("DB init error", e);
        }
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse res) {
        try {
            String user = req.getParameter("user");
            String pass = req.getParameter("pass");
            
            // Vulnerable SQL query construction
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username='" + user + "' AND password='" + pass + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            res.setContentType("text/html");
            PrintWriter out = res.getWriter();
            
            if (rs.next()) {
                out.println("<h2>Welcome " + rs.getString("username") + "!</h2>");
                out.println("<p>Message count: " + getMessageCount(rs.getInt("id")) + "</p>");
            } else {
                out.println("<h2>Login failed</h2>");
            }
            out.println("<a href=login.html>Back</a>");
            
        } catch (Exception e) {
            throw new RuntimeException("Query error", e);
        }
    }

    private int getMessageCount(int userId) {
        try {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(
                "SELECT COUNT(*) FROM messages WHERE user_id=" + userId);
            rs.next();
            return rs.getInt(1);
        } catch (Exception e) {
            throw new RuntimeException("Count error", e);
        }
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse res) {
        try {
            res.setContentType("text/html");
            PrintWriter out = res.getWriter();
            out.println("<form method=post>");
            out.println("User: <input name=user><br>");
            out.println("Pass: <input type=password name=pass><br>");
            out.println("<input type=submit value=Login>");
            out.println("</form>");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}