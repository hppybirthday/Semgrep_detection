package com.example.vulnerableapp;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.nio.file.*;
import java.util.logging.*;

/**
 * 文件下载Servlet，存在路径遍历漏洞
 * 尝试防御但存在逻辑缺陷
 */
public class FileDownloadServlet extends HttpServlet {
    private static final Logger logger = Logger.getLogger(FileDownloadServlet.class.getName());
    private static final String BASE_PATH = "/var/www/html/files/";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String fileName = request.getParameter("fileName");
        if (fileName == null || fileName.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file name parameter");
            return;
        }

        // 记录请求日志（防御式日志记录）
        logger.info("Download request for: " + fileName);

        try {
            // 不安全的路径拼接（漏洞点）
            String targetPath = BASE_PATH + fileName;
            
            // 基本路径规范化（防御尝试）
            File normalizedFile = new File(targetPath).getCanonicalFile();
            
            // 检查文件是否存在（防御检查）
            if (!normalizedFile.exists() || !normalizedFile.isFile()) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
                return;
            }
            
            // 二次检查防止路径穿越（存在绕过可能）
            if (!normalizedFile.getAbsolutePath().startsWith(BASE_PATH)) {
                logger.warning("Attempted path traversal detected: " + fileName);
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid file path");
                return;
            }

            // 设置响应头
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\\"" + fileName + "\\"");

            // 文件传输（易受攻击点）
            try (InputStream in = new FileInputStream(normalizedFile);
                 OutputStream out = response.getOutputStream()) {
                
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            
        } catch (IOException e) {
            logger.severe("File download error: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "File download failed");
        }
    }
}