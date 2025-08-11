import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

public class GuestbookServlet extends HttpServlet {
    private List<String> comments = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String comment = request.getParameter("comment");
        if (comment != null && !comment.isEmpty()) {
            comments.add(comment);
        }
        
        response.setContentType("text/html; charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        out.println("<html><head><title>Guestbook</title></head><body>");
        out.println("<h2>Leave a Comment:</h2>");
        out.println("<form method='post'>");
        out.println("<textarea name='comment'></textarea><br>");
        out.println("<input type='submit' value='Submit'>");
        out.println("</form><hr><h3>Comments:</h3>");
        
        if (comments.isEmpty()) {
            out.println("<p>No comments yet.</p>");
        } else {
            for (String c : comments) {
                out.println("<div style='border:1px solid;padding:10px;margin:10px 0;'>");
                out.println(c); // Vulnerable:直接输出用户输入内容
                out.println("</div>");
            }
        }
        
        out.println("</body></html>");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        doPost(request, response);
    }
}

/* 
Web.xml配置:
<servlet>
    <servlet-name>GuestbookServlet</servlet-name>
    <servlet-class>GuestbookServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>GuestbookServlet</servlet-name>
    <url-pattern>/guestbook</url-pattern>
</servlet-mapping>
*/