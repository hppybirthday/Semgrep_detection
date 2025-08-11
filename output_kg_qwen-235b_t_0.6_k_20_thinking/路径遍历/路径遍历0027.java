import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * CRM系统客户附件下载接口
 * 存在路径遍历漏洞
 */
public class CustomerAttachmentServlet extends HttpServlet {
    private static final String BASE_DIR = "/var/crm_data/";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
        throws ServletException, IOException {
        
        String customerId = req.getParameter("cid");
        String fileName = req.getParameter("file");
        
        if (customerId == null || fileName == null) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 构造文件路径（存在漏洞）
        String filePath = BASE_DIR + customerId + "/attachments/" + fileName;
        File file = new File(filePath);
        
        // 简单的文件存在检查（绕过方式：使用符号链接）
        if (!file.exists() || !file.canRead()) {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        // 设置响应头
        resp.setContentType("application/octet-stream");
        resp.setHeader("Content-Disposition", "attachment; filename=\\"" + fileName + "\\"");

        // 文件下载
        try (FileInputStream fis = new FileInputStream(file);
             ServletOutputStream sos = resp.getOutputStream()) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                sos.write(buffer, 0, bytesRead);
            }
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
        doGet(req, resp);
    }

    // 简单的客户验证（实际生产环境应连接数据库）
    private boolean isValidCustomer(String cid) {
        return cid.matches("[A-Z]{3}-\\d{6}");
    }

    // 记录访问日志（漏洞利用检测点）
    private void logAccess(String message) {
        System.out.println("[CRM-ATTACHMENT] " + message);
    }
}