package com.crm.fileupload;

import java.io.File;
import java.io.IOException;
import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import org.springframework.stereotype.Component;

@Component
@ServerEndpoint("/upload")
public class FileUploadEndpoint {
    
    @OnMessage
    public void onMessage(String filename, Session session) {
        try {
            // 模拟文件存储路径
            String storagePath = "/var/www/crm_uploads/";
            File uploadedFile = new File(storagePath + filename);
            
            // 创建文件（模拟上传过程）
            if (!uploadedFile.exists()) {
                uploadedFile.createNewFile();
            }
            
            // 执行文件转换命令（存在漏洞的代码）
            String convertCmd = "convert "+ uploadedFile.getAbsolutePath() +" "+ storagePath + "converted_"+filename;
            System.out.println("执行转换命令: " + convertCmd);
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", convertCmd});
            
            // 模拟响应
            session.getBasicRemote().sendText("文件处理完成");
            
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            try {
                session.getBasicRemote().sendText("处理失败: " + e.getMessage());
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }
}

// Spring Boot启动类（简化版）
@SpringBootApplication
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }
}

// WebSocket配置类（简化版）
@Configuration
@EnableWebSocket
public class WebSocketConfig {
    // 配置省略
}