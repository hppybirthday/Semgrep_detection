import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class XssVulnerableServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        out.println("<html><head><title>Data Cleaner</title></head><body>");
        out.println("<h2>Text Cleaning Service</h2>");
        out.println("<form method='post'>");
        out.println("Raw Input:<br><textarea name='text' rows='4' cols='50'></textarea><br>");
        out.println("<input type='submit' value='Clean Text'>");
        out.println("</form></body></html>");
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String userInput = req.getParameter("text");
        String cleaned = DataCleaner.process(userInput);
        
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        out.println("<html><body>");
        out.println("<h3>Cleaned Content:</h3>");
        out.println("<div style='border:1px solid;padding:10px;'>");
        out.println(cleaned);
        out.println("</div>");
        out.println("<br><a href='/'>Back</a></body></html>");
    }
}

class DataCleaner {
    static String process(String input) {
        // Simple whitespace normalization without HTML sanitization
        return input.replaceAll("\\s+", " ").trim();
    }
}