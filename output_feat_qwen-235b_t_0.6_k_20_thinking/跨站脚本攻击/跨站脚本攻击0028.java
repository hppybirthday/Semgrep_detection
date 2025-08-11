import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

@WebServlet("/profile")
public class ProfileServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String name = request.getParameter("name");
        request.setAttribute("username", name);
        request.getRequestDispatcher("/WEB-INF/profile.jsp").forward(request, response);
    }
}

// profile.jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>Profile</title></head>
<body>
    <h1>Welcome, <%= request.getAttribute("username") %></h1>
    <form method="post">
        <input type="text" name="name" value="<%= request.getAttribute("username") %>">
        <button type="submit">Update</button>
    </form>
</body>
</html>