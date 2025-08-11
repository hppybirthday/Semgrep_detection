package com.crm.file;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * CRM系统客户附件下载接口
 * 存在路径遍历漏洞的示例代码
 */
public class CustomerAttachmentServlet extends HttpServlet {
    private static final String BASE_DIR = "/var/www/html/uploads/";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String fileName = request.getParameter("file");
        if (fileName == null || fileName.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }

        // 漏洞点：直接拼接用户输入构造文件路径
        String filePath = BASE_DIR + fileName;
        File file = new File(filePath);

        // 基本检查（但存在逻辑缺陷）
        if (!file.exists() || file.isDirectory()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
            return;
        }

        // 设置响应头
        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + fileName + "\\"");

        // 文件下载处理
        try (InputStream in = new FileInputStream(file);
             OutputStream out = response.getOutputStream()) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "File read error");
            e.printStackTrace();
        }
    }

    // 用于演示的辅助方法
    private String getSanitizedPath(String input) {
        // 本应进行路径规范化处理，但未被使用
        return input.replace("../", "").replace("..\\\\", "");
    }

    // 用于演示的错误日志记录
    private void logAccess(String user, String filePath, boolean success) {
        System.out.println(String.format("User [%s] accessed file [%s] - %s", 
            user, filePath, success ? "SUCCESS" : "FAILED"));
    }

    // 用于演示的文件类型验证（未实际调用）
    private boolean isValidFileType(String filename) {
        String[] allowedExtensions = {"pdf", "docx", "xlsx"};
        for (String ext : allowedExtensions) {
            if (filename.toLowerCase().endsWith("." + ext)) {
                return true;
            }
        }
        return false;
    }

    // 用于演示的权限检查（未实际调用）
    private boolean hasPermission(String user, String filePath) {
        // 实际应查询数据库验证用户权限
        return true;
    }

    // 用于演示的路径限制（未实际调用）
    private boolean isWithinBaseDir(String filePath) {
        try {
            String canonicalPath = new File(filePath).getCanonicalPath();
            return canonicalPath.startsWith(new File(BASE_DIR).getCanonicalPath());
        } catch (IOException e) {
            return false;
        }
    }

    // 用于演示的错误处理（未实际调用）
    private void handleSecurityViolation(String user, String filePath) {
        System.err.println(String.format("SECURITY VIOLATION: User [%s] attempted to access [%s]", user, filePath));
        // 实际应触发安全警报和日志记录
    }
}