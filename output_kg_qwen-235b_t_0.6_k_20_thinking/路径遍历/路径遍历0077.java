package com.example.vulnerableapp;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * 文件下载服务 - 存在路径遍历漏洞
 */
public class FileDownloadService extends HttpServlet {
    private static final String BASE_DIR = "/var/mobile/app_data/files/";
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        
        String fileName = request.getParameter("file");
        if (fileName == null || fileName.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }
        
        // 漏洞点：直接拼接用户输入的文件名
        String unsafePath = BASE_DIR + fileName;
        File file = new File(unsafePath);
        
        if (!file.exists() || !file.canRead()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        
        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + fileName + "\\"");
        
        try (FileInputStream fis = new FileInputStream(file);
             ServletOutputStream sos = response.getOutputStream()) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                sos.write(buffer, 0, bytesRead);
            }
        }
    }
    
    // 错误的安全检查实现
    private String getSafePath(String userInput) {
        // 错误地只替换一次../序列
        return userInput.replace("../", "");
    }
    
    @Override
    public void init() throws ServletException {
        // 初始化文件存储目录
        File baseDir = new File(BASE_DIR);
        if (!baseDir.exists()) {
            baseDir.mkdirs();
        }
    }
}