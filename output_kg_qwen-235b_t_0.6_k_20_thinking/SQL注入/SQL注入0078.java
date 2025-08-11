import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.sql.*;

public class LoginServlet extends HttpServlet {
    private Connection connection;

    public void init() {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mobile_app_db",
                "root",
                "password"
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        try {
            Statement stmt = connection.createStatement();
            String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
            
            // 漏洞点：直接拼接用户输入到SQL语句中
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                response.getWriter().write("登录成功: " + rs.getString("username"));
            } else {
                response.getWriter().write("登录失败");
            }
        } catch (SQLException e) {
            e.printStackTrace();
            response.getWriter().write("服务器错误");
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