import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

// VulnerableServlet.java
public class VulnerableServlet extends HttpServlet {
    private List<String> comments = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String comment = request.getParameter("comment");
        if (comment != null && !comment.isEmpty()) {
            comments.add(comment);
        }
        response.sendRedirect("display.jsp");
    }
}

// DisplayServlet.java
public class DisplayServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        request.setAttribute("comments", ((VulnerableServlet) getServletConfig().getServletContext().getAttribute("vulnServlet")).comments);
        request.getRequestDispatcher("display.jsp").forward(request, response);
    }
}

// display.jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>Vulnerable Forum</title></head>
<body>
    <h1>Comments Section</h1>
    <form action="submit" method="post">
        <textarea name="comment"></textarea>
        <input type="submit" value="Post Comment">
    </form>
    
    <div id="comments">
        <% for (String comment : (List<String>)request.getAttribute("comments")) { %>
            <div class="comment"><%= comment %></div>
        <% } %>
    </div>
</body>
</html>

// web.xml配置
<servlet>
    <servlet-name>VulnerableServlet</servlet-name>
    <servlet-class>VulnerableServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>VulnerableServlet</servlet-name>
    <url-pattern>/submit</url-pattern>
</servlet-mapping>

<servlet>
    <servlet-name>DisplayServlet</servlet-name>
    <servlet-class>DisplayServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>DisplayServlet</servlet-name>
    <url-pattern>/display</url-pattern>
</servlet-mapping>