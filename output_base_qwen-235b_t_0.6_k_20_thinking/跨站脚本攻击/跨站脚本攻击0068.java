import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class XSSVulnerableServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchQuery = request.getParameter("search");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h2>Search Results for: " + searchQuery + "</h2>");
        out.println("<div>You searched for: " + searchQuery + "</div>");
        out.println("<form method='post'>");
        out.println("<input type='text' name='search' value='" + searchQuery + "'>");
        out.println("<input type='submit' value='Search'>");
        out.println("</form></body></html>");
        out.close();
    }
}

/* web.xml配置
<servlet>
    <servlet-name>XSSVulnerableServlet</servlet-name>
    <servlet-class>XSSVulnerableServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>XSSVulnerableServlet</servlet-name>
    <url-pattern>/search</url-pattern>
</servlet-mapping>
*/