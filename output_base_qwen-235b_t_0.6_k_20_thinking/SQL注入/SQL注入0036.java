import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class VulnerableLoginServlet extends HttpServlet {
    private Connection connection;

    public void init() {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", "root", "password");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        try {
            Statement statement = connection.createStatement();
            // 漏洞点：直接拼接用户输入到SQL查询中
            String query = "SELECT * FROM users WHERE username = '" + username + 
                          "' AND password = '" + password + "'";
            
            out.println("<!-- DEBUG: Executing SQL: " + query + " -->");
            ResultSet resultSet = statement.executeQuery(query);
            
            if (resultSet.next()) {
                out.println("<h1>Welcome " + username + "!</h1>");
                out.println("<p>Admin panel: <a href='/admin'>Go to admin</a></p>");
            } else {
                out.println("<h1>Login failed</h1>");
                out.println("<p>Invalid credentials</p>");
            }
            
        } catch (SQLException e) {
            out.println("<h1>Database error</h1>");
            out.println("<p>" + e.getMessage() + "</p>");
        }
    }

    public void destroy() {
        try {
            if (connection != null) connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}