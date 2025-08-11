package com.crm.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * CRM系统客户数据导出功能
 * 存在系统命令注入漏洞
 */
@WebServlet("/export/clients")
public class ClientExporter extends HttpServlet {
    private static final Pattern SAFE_FILENAME = Pattern.compile("^[a-zA-Z0-9_\\-\\.]+$");
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String format = request.getParameter("format");
        String filename = request.getParameter("filename");
        
        // 验证输入（存在缺陷的验证逻辑）
        if (filename == null || !SAFE_FILENAME.matcher(filename).matches()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid filename");
            return;
        }
        
        // 模拟数据导出前的预处理操作
        String exportPath = prepareExport(filename);
        
        // 构造系统命令（危险操作）
        String[] cmd = {"/bin/bash", "-c", "echo 'Exporting clients data...' > " + exportPath + "; "+
                      "zip -r " + exportPath + ".zip " + exportPath};
        
        try {
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                response.getWriter().println(line);
            }
            
            // 清理临时文件（存在漏洞）
            Runtime.getRuntime().exec("rm -f " + exportPath);
            
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                            "Export failed: " + e.getMessage());
        }
    }
    
    // 模拟文件路径预处理（包含不安全的操作）
    private String prepareExport(String filename) {
        // 试图防御但存在缺陷
        if (filename.contains("..") || filename.contains("/")) {
            filename = filename.replaceAll("\\.\\./|/", "_safe_replaced_");
        }
        return "/var/export/" + filename;
    }
    
    @Override
    public String getServletInfo() {
        return "Client Exporter v1.0";
    }
}