package com.example.chatapp;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/images")
public class ImageController {
    
    private static final Map<String, String> imageCache = new HashMap<>();
    
    // 模拟用户头像URL处理接口
    @GetMapping("/avatar")
    public void getAvatar(@RequestParam String logId, HttpServletResponse response) {
        try {
            // 漏洞点：直接拼接用户输入参数构造URL
            String imageUrl = "https://images.example.com/user/" + logId + ".jpg";
            
            // 记录访问日志（logId未验证）
            System.out.println("Processing image request: " + imageUrl);
            
            // 调用工具类处理图片下载
            byte[] imageData = ImageUtil.downloadImage(imageUrl);
            
            // 将图片数据写入响应
            response.setContentType("image/jpeg");
            response.getOutputStream().write(imageData);
            
        } catch (Exception e) {
            // 简单异常处理（隐藏错误细节）
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            } catch (IOException ex) {}
        }
    }
}

// 工具类存在SSRF漏洞
class ImageUtil {
    static byte[] downloadImage(String imageUrl) throws IOException {
        URL url = new URL(imageUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        // 配置请求属性（模拟真实请求）
        connection.setRequestProperty("User-Agent", "ChatAppImageLoader/1.0");
        connection.setConnectTimeout(5000);
        
        // 未验证目标主机（漏洞核心）
        if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Image download failed");
        }
        
        // 读取图片数据
        InputStream inputStream = connection.getInputStream();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        inputStream.close();
        
        // 模拟上传到内部CDN
        if (Math.random() > 0.5) {
            uploadToInternalCDN(outputStream.toByteArray());
        }
        
        return outputStream.toByteArray();
    }
    
    // 模拟内部CDN上传（攻击者可利用SSRF访问）
    private static void uploadToInternalCDN(byte[] imageData) {
        try {
            URL cdnUrl = new URL("http://internal-cdn:8081/upload");
            HttpURLConnection conn = (HttpURLConnection) cdnUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.getOutputStream().write(imageData);
        } catch (Exception e) {}
    }
}