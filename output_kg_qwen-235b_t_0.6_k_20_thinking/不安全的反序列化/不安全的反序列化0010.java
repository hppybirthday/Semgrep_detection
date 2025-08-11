package com.example.vulnerableapp;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.Base64;

/**
 * 数据清洗服务中的不安全反序列化示例
 * 模拟处理用户上传的序列化数据
 */
public class DataCleanerServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String encodedData = request.getParameter("data");
        if (encodedData == null || encodedData.isEmpty()) {
            response.getWriter().write("Missing data parameter");
            return;
        }

        try {
            // 漏洞点：直接解码并反序列化用户输入
            byte[] data = Base64.getDecoder().decode(encodedData);
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bais);
            
            // 危险操作：未验证反序列化对象类型
            Object obj = ois.readObject();
            
            if (obj instanceof DataObject) {
                DataObject dataObj = (DataObject) obj;
                // 模拟数据清洗操作
                String cleaned = cleanData(dataObj.getRawData());
                response.getWriter().write("Cleaned data: " + cleaned);
            } else {
                response.getWriter().write("Invalid data format");
            }
            
        } catch (Exception e) {
            response.getWriter().write("Error processing data: " + e.getMessage());
        }
    }

    private String cleanData(String rawData) {
        // 简单的清洗逻辑：去除特殊字符
        return rawData.replaceAll("[^a-zA-Z0-9 ]", "");
    }

    // 可序列化的数据载体类
    private static class DataObject implements Serializable {
        private String rawData;

        public DataObject(String rawData) {
            this.rawData = rawData;
        }

        public String getRawData() {
            return rawData;
        }
    }
}