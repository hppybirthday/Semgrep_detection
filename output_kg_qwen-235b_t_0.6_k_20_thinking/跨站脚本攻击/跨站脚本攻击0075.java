package com.example.xssdemo;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.commons.fileupload.*;
import org.apache.commons.fileupload.disk.*;
import org.apache.commons.fileupload.servlet.*;
import java.util.*;

public class FileEncryptServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        // 检查是否为文件上传请求
        if (ServletFileUpload.isMultipartContent(request)) {
            try {
                // 创建文件上传处理工厂
                DiskFileItemFactory factory = new DiskFileItemFactory();
                ServletFileUpload upload = new ServletFileUpload(factory);
                
                // 解析请求中的文件项
                List<FileItem> items = upload.parseRequest(request);
                String filename = "";
                
                // 处理文件上传
                for (FileItem item : items) {
                    if (!item.isFormField()) {
                        filename = item.getName();
                        // 模拟文件加密处理
                        byte[] encrypted = encryptData(item.getInputStream().readAllBytes());
                        // 保存加密文件（此处省略实际存储逻辑）
                        System.out.println("Encrypted file saved: " + filename);
                    }
                }
                
                // 生成响应页面（存在XSS漏洞）
                response.setContentType("text/html;charset=UTF-8");
                PrintWriter out = response.getWriter();
                out.println("<!DOCTYPE html>\
" +
                    "<html>\
" +
                    "<head><title>Upload Result</title></head>\
" +
                    "<body>\
" +
                    "<h2>文件处理成功！</h2>\
" +
                    "<p>已处理文件: " + filename + "</p>\
" +  // 漏洞点：未转义用户输入
                    "<script>\
" +
                    "document.write('上次处理时间: ' + document.lastModified);\
" +
                    "</script>\
" +
                    "</body>\
" +
                    "</html>");
                
            } catch (Exception ex) {
                throw new ServletException("File upload error", ex);
            }
        }
    }
    
    // 模拟加密函数
    private byte[] encryptData(byte[] data) {
        // 实际加密逻辑应使用安全算法
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte)(data[i] ^ 0xAA);
        }
        return data;
    }
    
    // GET请求返回上传表单
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.println("<!DOCTYPE html>\
" +
            "<html>\
" +
            "<head><title>File Encrypt</title></head>\
" +
            "<body>\
" +
            "<h2>文件加密工具</h2>\
" +
            "<form method=\\"post\\" enctype=\\"multipart/form-data\\">\
" +
            "<input type=\\"file\\" name=\\"file\\">\
" +
            "<input type=\\"submit\\" value=\\"加密文件\\">\
" +
            "</form>\
" +
            "</body>\
" +
            "</html>");
    }
}