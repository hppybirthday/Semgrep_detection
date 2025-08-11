package com.bank.filemanager;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * 银行客户文件下载控制器
 * 存在路径遍历漏洞的示例实现
 */
public class FinancialDocumentServlet extends HttpServlet {
    private static final String BASE_DIR = "/var/bank/customer_docs/";
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("pdf", "csv", "xlsx");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String fileName = request.getParameter("file");
        if (fileName == null || fileName.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }

        // 漏洞点：直接拼接用户输入的文件名
        Path filePath = Paths.get(BASE_DIR, fileName);
        
        if (!isValidFileExtension(fileName)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "File type not allowed");
            return;
        }

        if (!isSubPathOf(filePath, BASE_DIR)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

        try (InputStream fileInputStream = new FileInputStream(filePath.toFile())) {
            response.setContentType(getServletContext().getMimeType(fileName));
            response.setHeader("Content-Disposition", "inline; filename=\\"" + fileName + "\\"");
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
        } catch (FileNotFoundException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
        }
    }

    private boolean isValidFileExtension(String fileName) {
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex == -1) return false;
        
        String extension = fileName.substring(dotIndex + 1).toLowerCase();
        return ALLOWED_EXTENSIONS.contains(extension);
    }

    private boolean isSubPathOf(Path child, String parentDir) {
        try {
            Path parentPath = Paths.get(parentDir).toRealPath();
            Path childPath = child.toRealPath();
            return childPath.startsWith(parentPath);
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        doGet(request, response);
    }
}