import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * 模拟文件下载功能的Servlet，存在路径遍历漏洞
 */
public class VulnerableFileDownloadServlet extends HttpServlet {
    private static final String BASE_DIR = "/var/www/files/";
    private static final int BUFFER_SIZE = 4096;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户请求的文件名参数
        String filename = request.getParameter("filename");
        
        // 参数校验
        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, 
                              "Filename parameter is required");
            return;
        }

        // 漏洞点：直接拼接用户输入到文件路径
        File file = new File(BASE_DIR + filename);
        
        // 检查文件是否存在
        if (!file.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND,
                              "The requested file does not exist.");
            return;
        }

        // 检查文件可读性
        if (!file.canRead()) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                              "No permission to read the file.");
            return;
        }

        // 设置响应头
        String mimeType = getServletContext().getMimeType(filename);
        if (mimeType == null) {
            mimeType = "application/octet-stream";
        }
        response.setContentType(mimeType);
        response.setHeader("Content-Disposition", "inline; filename=\\"" + filename + "\\"");
        response.setContentLength((int) file.length());

        // 文件传输
        try (FileInputStream fileInputStream = new FileInputStream(file);
             BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
             ServletOutputStream servletOutputStream = response.getOutputStream()) {
            
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = bufferedInputStream.read(buffer)) != -1) {
                servletOutputStream.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            throw new ServletException("Error occurred while reading the file", e);
        }
    }
}