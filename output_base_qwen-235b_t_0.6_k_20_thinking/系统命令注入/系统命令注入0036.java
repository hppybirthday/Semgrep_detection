import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileViewerServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String filename = request.getParameter("file");
        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }
        
        ProcessBuilder processBuilder = new ProcessBuilder("/bin/sh", "-c", "cat " + filename);
        processBuilder.redirectErrorStream(true);
        
        try {
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            response.setContentType("text/plain");
            PrintWriter out = response.getWriter();
            String line;
            while ((line = reader.readLine()) != null) {
                out.println(line);
            }
            
        } catch (Exception e) {
            throw new ServletException("Error executing command", e);
        }
    }
}

// web.xml配置示例
/*
<servlet>
    <servlet-name>FileViewer</servlet-name>
    <servlet-class>FileViewerServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>FileViewer</servlet-name>
    <url-pattern>/view</url-pattern>
</servlet-mapping>
*/