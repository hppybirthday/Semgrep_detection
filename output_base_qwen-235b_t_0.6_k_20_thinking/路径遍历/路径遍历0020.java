import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileDownloadServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String filename = request.getParameter("file");
        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }

        String basePath = "/var/www/html/resources/";
        File file = new File(basePath + filename);
        
        if (!file.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
            return;
        }

        if (filename.contains("..") || filename.contains(":\")) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid characters in filename");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + filename + "\\"");

        try (FileInputStream fis = new FileInputStream(file);
             OutputStream os = response.getOutputStream()) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
        }
    }
}

/*
web.xml配置：
<servlet>
    <servlet-name>FileDownload</servlet-name>
    <servlet-class>FileDownloadServlet</servlet-class>
</servlet>
<servlet-mapping>
    <url-pattern>/download</url-pattern>
</servlet-mapping>
*/