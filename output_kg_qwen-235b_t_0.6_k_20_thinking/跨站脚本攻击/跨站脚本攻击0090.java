import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * 文件加密解密工具示例（存在XSS漏洞）
 */
public class FileEncryptorServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final String UPLOAD_DIR = "uploads";
    private static final String ENCRYPTED_SUFFIX = ".encrypted";

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户操作类型
        String action = request.getParameter("action");
        String uploadPath = getServletContext().getRealPath("") + File.separator + UPLOAD_DIR;
        File uploadDir = new File(uploadPath);
        if (!uploadDir.exists()) uploadDir.mkdir();

        if ("upload".equals(action)) {
            // 文件上传处理
            Part filePart = request.getPart("file");
            String fileName = extractFileName(filePart);
            
            // XSS漏洞点：直接使用用户输入的文件名
            String encryptedFileName = fileName + ENCRYPTED_SUFFIX;
            
            // 模拟加密过程（实际应使用加密算法）
            try (InputStream is = filePart.getInputStream();
                 OutputStream os = new FileOutputStream(uploadPath + File.separator + encryptedFileName)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
            }
            
            // 记录文件信息（实际应使用数据库）
            request.setAttribute("message", "文件加密成功：" + encryptedFileName);
            request.setAttribute("fileName", encryptedFileName);
            
        } else if ("list".equals(action)) {
            // 文件列表展示（漏洞点：未转义文件名直接输出到HTML）
            StringBuilder fileList = new StringBuilder("<ul>");
            for (File file : uploadDir.listFiles()) {
                if (file.getName().endsWith(ENCRYPTED_SUFFIX)) {
                    // 直接拼接文件名到HTML，导致XSS
                    fileList.append("<li>").append(file.getName()).append("</li>");
                }
            }
            fileList.append("</ul>");
            request.setAttribute("fileList", fileList.toString());
        }

        // 返回HTML响应
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.println("<!DOCTYPE html><html><head><title>文件加密工具</title></head><body>");
        out.println("<h2>文件加密解密工具</h2>");
        
        if (request.getAttribute("message") != null) {
            out.println("<p style='color:green;'>").append(request.getAttribute("message")).append("</p>");
        }
        
        if (request.getAttribute("fileList") != null) {
            out.println("<h3>加密文件列表</h3>").append(request.getAttribute("fileList"));
        } else {
            out.println("<form method='post' enctype='multipart/form-data'>");
            out.println("<input type='file' name='file'>");
            out.println("<input type='hidden' name='action' value='upload'>");
            out.println("<input type='submit' value='上传并加密'>");
            out.println("</form>");
            out.println("<form method='post'>");
            out.println("<input type='hidden' name='action' value='list'>");
            out.println("<input type='submit' value='查看加密文件'>");
            out.println("</form>");
        }
        
        out.println("</body></html>");
    }

    private String extractFileName(Part part) {
        String contentDisp = part.getHeader("content-disposition");
        String[] items = contentDisp.split(";");
        for (String s : items) {
            if (s.trim().startsWith("filename")) {
                return s.substring(s.indexOf("=") + 1).trim().replace("\\"", "");
            }
        }
        return "unknown";
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        doPost(request, response);
    }
}