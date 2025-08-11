package com.example.datacleaner;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 数据清洗服务端点，存在不安全反序列化漏洞
 */
@WebServlet("/cleandata")
public class DataCleaningServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 1. 接收用户提交的base64编码数据
        String encodedData = request.getParameter("data");
        if (encodedData == null || encodedData.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing data parameter");
            return;
        }
        
        // 2. 解码并反序列化数据
        try {
            byte[] serializedData = Base64.getDecoder().decode(encodedData);
            ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
            ObjectInputStream ois = new ObjectInputStream(bais);
            
            // 3. 存在漏洞的关键调用：直接反序列化不可信数据
            Object rawData = ois.readObject();
            
            // 4. 数据清洗逻辑（示例）
            if (rawData instanceof DataRecord) {
                DataRecord record = (DataRecord) rawData;
                // 模拟清洗过程
                record.setContent(record.getContent().trim().toUpperCase());
                response.getWriter().println("Cleaned record: " + record);
            } else {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid data type");
            }
            
        } catch (Exception e) {
            // 5. 简单的异常处理（实际可能更复杂）
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Processing failed");
            e.printStackTrace();
        }
    }
}

// 数据模型类（需要实现序列化）
class DataRecord implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private String content;
    private int recordId;
    
    public DataRecord() {}
    
    public DataRecord(int recordId, String content) {
        this.recordId = recordId;
        this.content = content;
    }
    
    public String getContent() {
        return content;
    }
    
    public void setContent(String content) {
        this.content = content;
    }
    
    @Override
    public String toString() {
        return "Record[ID=" + recordId + ", Content='" + content + "']";
    }
}