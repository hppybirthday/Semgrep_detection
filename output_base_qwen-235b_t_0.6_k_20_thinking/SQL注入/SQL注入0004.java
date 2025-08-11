import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.sql.*;

public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            // 数据库连接配置
            String dbURL = "jdbc:mysql://localhost:3306/mydb";
            String dbUser = "root";
            String dbPassword = "secure123";
            
            // 建立数据库连接
            conn = DriverManager.getConnection(dbURL, dbUser, dbPassword);
            
            // 漏洞点：直接拼接SQL语句
            String sql = "SELECT * FROM users WHERE username = '" + 
                        username + "' AND password = '" + password + "'";
            
            stmt = conn.createStatement();
            rs = stmt.executeQuery(sql);
            
            if (rs.next()) {
                // 登录成功逻辑
                HttpSession session = request.getSession();
                session.setAttribute("user", rs.getString("username"));
                response.sendRedirect("dashboard.jsp");
            } else {
                // 登录失败处理
                request.setAttribute("error", "Invalid credentials");
                request.getRequestDispatcher("login.jsp").forward(request, response);
            }
            
        } catch (SQLException e) {
            // 错误处理
            e.printStackTrace();
            request.setAttribute("error", "Database error: " + e.getMessage());
            try {
                if (conn != null) conn.rollback();
            } catch (SQLException ex) {
                ex.printStackTrace();
            }
            request.getRequestDispatcher("error.jsp").forward(request, response);
        } finally {
            // 资源清理
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
}