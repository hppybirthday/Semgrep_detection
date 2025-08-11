package com.crm.file;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * CRM客户合同文件下载控制器
 * 存在路径遍历漏洞
 */
public class ContractDownloadServlet extends HttpServlet {
    // 基础目录配置
    private static final String BASE_DIR = "/var/crm/contracts/";
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户输入的文件名参数
        String filename = request.getParameter("file");
        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }
        
        // 构造文件路径（存在漏洞的写法）
        String filePath = BASE_DIR + filename;
        File file = new File(filePath);
        
        // 验证文件是否存在
        if (!file.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
            return;
        }
        
        // 设置响应头
        response.setContentType("application/pdf");
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + filename + "\\"");
        
        // 读取并输出文件内容
        try (InputStream in = new FileInputStream(file);
             OutputStream out = response.getOutputStream()) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }
    
    // 模拟日志记录功能
    private void logAccess(String message) {
        System.out.println("[CONTRACT_ACCESS] " + message);
    }
    
    // 初始化检查
    @Override
    public void init() throws ServletException {
        File baseDir = new File(BASE_DIR);
        if (!baseDir.exists() && !baseDir.mkdirs()) {
            throw new ServletException("Failed to create base directory: " + BASE_DIR);
        }
    }
}