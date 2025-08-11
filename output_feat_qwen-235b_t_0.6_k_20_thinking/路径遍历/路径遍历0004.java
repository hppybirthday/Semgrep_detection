package com.example.vulnerableapp;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 文件生成工具类（存在路径遍历漏洞）
 */
public class FileGeneratorServlet extends HttpServlet {
    private static final String BASE_DIR = "/var/www/uploads/";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户输入的文件名
        String userInput = request.getParameter("fileName");
        
        // 检查输入是否为空
        if (userInput == null || userInput.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "File name is required");
            return;
        }
        
        // 构造文件路径（漏洞点：直接拼接用户输入）
        File targetFile = new File(BASE_DIR + userInput);
        
        // 防御式编程：检查父目录是否存在
        if (!targetFile.getParentFile().exists()) {
            targetFile.getParentFile().mkdirs();
        }
        
        // 写入文件内容
        try (FileWriter writer = new FileWriter(targetFile)) {
            writer.write("Generated content for " + userInput);
            response.getWriter().println("File created: " + userInput);
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "File creation failed");
        }
    }

    // 路径规范化工具方法（未被调用的防御措施）
    private String normalizePath(String path) {
        return new File(path).getCanonicalPath();
    }
}