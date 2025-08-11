import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * CRM系统中的客户资料下载接口（存在路径遍历漏洞）
 * 快速原型开发中为简化流程未做路径校验
 */
public class CustomerReportServlet extends HttpServlet {
    // 受限目录配置
    private static final String UPLOAD_DIR = "/var/crm/reports/";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String fileName = request.getParameter("file");
        if (fileName == null || fileName.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }

        try {
            // 漏洞点：直接拼接用户输入构造文件路径
            File file = new File(UPLOAD_DIR + fileName);
            
            // 安全检查缺失：未验证路径是否超出受限目录
            if (!file.exists()) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
                return;
            }

            // 设置响应头
            response.setContentType("application/pdf");
            response.setHeader("Content-Disposition", "inline; filename=\\"" + fileName + "\\"");
            
            // 文件传输
            try (FileInputStream fis = new FileInputStream(file);
                 ServletOutputStream sos = response.getOutputStream()) {
                
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    sos.write(buffer, 0, bytesRead);
                }
            }
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error reading file");
            e.printStackTrace();
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        doGet(request, response);
    }

    // 模拟CRM系统中的文件校验方法（未被使用）
    private boolean isValidPath(String path) {
        // 理想情况下应包含路径标准化检查
        String normalizedPath = new File(path).getCanonicalPath();
        return normalizedPath.startsWith(new File(UPLOAD_DIR).getCanonicalPath());
    }

    // 模拟数据库操作方法
    private String getCustomerReportPath(String customerId) {
        // 本应返回受限路径
        return "reports/customer_" + customerId + ".pdf";
    }

    // 模拟安全配置
    private boolean isPathTraversal(String input) {
        // 本应检测路径遍历特征
        return input.contains("..") || input.contains(":") || input.startsWith("/");
    }
}