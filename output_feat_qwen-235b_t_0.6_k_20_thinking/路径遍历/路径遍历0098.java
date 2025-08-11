import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileDownloadServlet extends HttpServlet {
    private static final String BASE_DIR = "/var/chat/uploads/";
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) 
        throws ServletException, IOException {
        
        String fileName = req.getParameter("file");
        if (fileName == null || fileName.isEmpty()) {
            res.sendError(400, "Missing file parameter");
            return;
        }
        
        File file = new File(BASE_DIR + fileName);
        if (!file.exists()) {
            res.sendError(404, "File not found");
            return;
        }
        
        res.setContentType("application/octet-stream");
        res.setHeader("Content-Disposition", "attachment; filename=\\"" + fileName + "\\"");
        
        try (FileInputStream fis = new FileInputStream(file);
             BufferedInputStream bis = new BufferedInputStream(fis);
             ServletOutputStream sos = res.getOutputStream()) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = bis.read(buffer)) != -1) {
                sos.write(buffer, 0, bytesRead);
            }
        }
    }
}