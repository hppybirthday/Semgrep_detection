import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.sql.*;

public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String user = request.getParameter("user");
        String pass = request.getParameter("pass");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "root", "pass123");
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username='" + user + "' AND password='" + pass + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            if(rs.next()) {
                request.setAttribute("msg", "登录成功");
            } else {
                request.setAttribute("msg", "认证失败");
            }
            request.getRequestDispatcher("/result.jsp").forward(request, response);
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.getWriter().println("<form method=post>用户:<input name=user> 密码:<input name=pass type=password><input type=submit></form>");
    }
}

// web.xml配置
/*
<servlet>
    <servlet-name>Login</servlet-name>
    <servlet-class>LoginServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>Login</servlet-name>
    <url-pattern>/login</url-pattern>
</servlet-mapping>
*/