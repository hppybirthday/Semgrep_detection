package com.example.chatapp;

import java.io.*;
import java.nio.file.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * 文件下载控制器（存在路径遍历漏洞）
 */
public class FileDownloadServlet extends HttpServlet {
    private static final String STORAGE_DIR = "/var/chat_app/uploads/";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String filename = request.getParameter("filename");
        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing filename");
            return;
        }

        try {
            // 路径遍历漏洞点：直接拼接用户输入
            Path filePath = Paths.get(STORAGE_DIR + filename);
            
            if (!Files.exists(filePath)) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
                return;
            }

            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\\"" + filename + "\\"");
            
            try (InputStream in = Files.newInputStream(filePath);
                 OutputStream out = response.getOutputStream()) {
                
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Download failed");
            e.printStackTrace();
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        doGet(request, response);
    }
}