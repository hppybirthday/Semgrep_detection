import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.logging.Logger;
import java.util.logging.Level;

public class XSSVulnerableServlet extends HttpServlet {
    private static final Logger logger = Logger.getLogger(XSSVulnerableServlet.class.getName());

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String requestedPath = request.getParameter("path");
        response.setContentType("text/html");
        
        try {
            // 模拟业务逻辑处理
            processRequest(requestedPath);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error processing request: " + requestedPath, e);
            String errorPage = generateErrorPage(requestedPath, e.getMessage());
            response.getWriter().write(errorPage);
        }
    }

    private void processRequest(String path) throws Exception {
        // 模拟路径处理逻辑
        if (path == null || path.isEmpty() || path.contains("..") || path.contains("<script>")) {
            throw new Exception("Invalid path: " + path);
        }
        // 实际业务逻辑...
    }

    private String generateErrorPage(String path, String errorMessage) {
        return String.format(
            "<!DOCTYPE html>\
" +
            "<html>\
" +
            "<head>\
" +
            "    <title>Error 404</title>\
" +
            "    <link rel=\\"icon\\" href=\\"%s\\">\
" +
            "</head>\
" +
            "<body>\
" +
            "    <h1>Page Not Found</h1>\
" +
            "    <p>The requested path <b>%s</b> could not be processed.</p>\
" +
            "    <p>Error: %s</p>\
" +
            "    <img src=\\"%s\\" onerror=\\"javascript:alert('XSS攻击已触发！');\\">\
" +
            "</body>\
" +
            "</html>",
            path, path, errorMessage, path
        );
    }
}