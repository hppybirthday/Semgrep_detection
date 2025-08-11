package com.crm.example;

import java.io.*;
import java.nio.file.*;
import java.util.function.*;
import javax.servlet.http.*;

/**
 * CRM系统客户文档下载功能
 * 存在路径遍历漏洞
 */
public class CustomerDocumentController {
    // 基础存储路径
    private static final String BASE_PATH = "/var/www/crm_uploads/";

    /**
     * 下载客户文档接口
     * 漏洞点：未过滤用户输入中的../路径
     */
    public void downloadDocument(HttpServletRequest request, HttpServletResponse response) {
        String fileName = request.getParameter("fileName");
        
        // 函数式编程处理文件流
        Consumer<HttpServletResponse> fileWriter = res -> {
            try {
                // 构造文件路径（存在漏洞）
                Path filePath = Paths.get(BASE_PATH + fileName);
                
                // 检查文件是否存在
                if (!Files.exists(filePath)) {
                    res.sendError(HttpServletResponse.SC_NOT_FOUND, "文件不存在");
                    return;
                }

                // 设置响应头
                res.setContentType("application/octet-stream");
                res.setHeader("Content-Disposition", "attachment; filename=\\"" + fileName + "\\"");

                // 读取文件流
                try (InputStream in = Files.newInputStream(filePath);
                     OutputStream out = res.getOutputStream()) {
                    
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                }
            } catch (Exception e) {
                try {
                    res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "下载失败");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        };
        
        // 执行文件写入
        fileWriter.accept(response);
    }

    /**
     * 单元测试示例（模拟请求）
     */
    public static void main(String[] args) {
        CustomerDocumentController controller = new CustomerDocumentController();
        
        // 模拟HTTP请求
        HttpServletRequest request = mockRequest("fileName", "../../../../etc/passwd");
        HttpServletResponse response = mockResponse();
        
        // 触发下载
        controller.downloadDocument(request, response);
    }

    // 模拟请求对象（简化版）
    private static HttpServletRequest mockRequest(String paramName, String paramValue) {
        return new HttpServletRequest() {
            @Override
            public String getParameter(String name) {
                return paramName.equals(name) ? paramValue : null;
            }
            // 其他方法省略...
        };
    }

    // 模拟响应对象（简化版）
    private static HttpServletResponse mockResponse() {
        return new HttpServletResponse() {
            @Override
            public void setContentType(String type) {}
            
            @Override
            public void setHeader(String name, String value) {}
            
            @Override
            public ServletOutputStream getOutputStream() {
                return new ServletOutputStream() {
                    @Override
                    public boolean isReady() { return true; }
                    
                    @Override
                    public void setWriteListener(ServletOutputStream.WriteListener writeListener) {}
                    
                    @Override
                    public void write(int b) {}
                };
            }
            // 其他方法省略...
        };
    }
}