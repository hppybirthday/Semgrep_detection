import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DataCleaner extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        PrintWriter out = res.getWriter();
        String userInput = req.getParameter("name");
        String cleaned = cleanData(userInput);
        res.setContentType("text/html");
        out.println("<html><body>");
        out.println("Welcome, " + cleaned);
        out.println("</body></html>");
    }

    private String cleanData(String data) {
        // Flawed sanitization: only removes lowercase script tags
        return data.replace("<script>", "").replace("</script>", "");
    }
}

// web.xml配置
/*
<servlet>
    <servlet-name>DataCleaner</servlet-name>
    <servlet-class>DataCleaner</servlet-class>
</servlet>
<servlet-mapping>
    <url-pattern>/clean</url-pattern>
</servlet-mapping>
*/

// Vulnerable HTML form
/*
<html>
<body>
<form action="clean" method="POST">
    Name: <input type="text" name="name">
    <input type="submit">
</form>
</body>
</html>
*/