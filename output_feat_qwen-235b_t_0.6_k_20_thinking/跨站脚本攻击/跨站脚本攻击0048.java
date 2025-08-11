import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileEncryptor extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static String storedFileName = "";
    private static String storedContent = "";

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String action = request.getParameter("action");
        String fileName = request.getParameter("filename");
        String content = request.getParameter("content");
        
        if("encrypt".equals(action) && fileName != null && content != null) {
            storedFileName = fileName;
            storedContent = encrypt(content);
            response.sendRedirect("/view?file=" + fileName);
            return;
        }
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>File Encryptor</h1>");
        out.println("<form method=post>");
        out.println("Action: <select name=action><option value=encrypt>Encrypt</option></select><br>");
        out.println("Filename: <input type=text name=filename value='"+fileName+"'><br>");
        out.println("Content: <textarea name=content>"+content+"</textarea><br>");
        out.println("<input type=submit value=Submit>");
        out.println("</form></body></html>");
    }

    private String encrypt(String input) {
        return "ENCRYPTED:" + input.hashCode();
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fileName = request.getParameter("file");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h2>Encrypted File: " + fileName + "</h2>");
        out.println("<div style='border:1px solid #000;padding:10px;'>");
        out.println("Stored Content: " + storedContent);
        out.println("</div>");
        out.println("<p>Download count: <span id='count'>0</span></p>");
        out.println("<script src='/stats.js'></script>");
        out.println("</body></html>");
    }
}