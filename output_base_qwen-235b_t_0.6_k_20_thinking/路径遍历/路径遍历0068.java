import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileDownloadServlet extends HttpServlet {
    private static final String BASE_PATH = "/var/www/html/files/";

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fileName = request.getParameter("file");
        if (fileName == null || fileName.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }

        File file = new File(BASE_PATH + fileName);
        if (!file.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + fileName + "\\"");

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
Web.xml配置示例：
<servlet>
    <servlet-name>FileDownload</servlet-name>
    <servlet-class>FileDownloadServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>FileDownload</servlet-name>
    <url-pattern>/download</url-pattern>
</servlet-mapping>
*/