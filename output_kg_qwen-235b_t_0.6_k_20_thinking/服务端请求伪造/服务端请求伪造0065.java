package com.example.chatapp;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

@RestController
@RequestMapping("/api/images")
public class ImageController {
    // 模拟聊天应用中用户发送图片链接的场景
    // 用户发送的URL参数未经过滤，直接用于服务器请求
    @GetMapping("/fetch")
    public void fetchExternalImage(@RequestParam String url, HttpServletResponse response) {
        try {
            // 存在漏洞的代码：直接使用用户提供的URL发起请求
            URL imageUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) imageUrl.openConnection();
            connection.setRequestMethod("GET");
            
            // 读取响应头设置到客户端
            response.setContentType(connection.getContentType());
            
            // 读取响应流并写入客户端
            try (InputStream in = connection.getInputStream();
                 OutputStream out = response.getOutputStream()) {
                
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            
        } catch (Exception e) {
            // 简单的异常处理，没有记录详细日志
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
    
    // 模拟聊天应用中显示本地图片的接口
    @GetMapping("/{id}")
    public void getLocalImage(@PathVariable String id, HttpServletResponse response) {
        try {
            // 模拟从本地路径读取图片
            File imageFile = new File("/var/images/chat/" + id + ".jpg");
            if (!imageFile.exists()) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }
            
            response.setContentType("image/jpeg");
            try (InputStream in = new FileInputStream(imageFile);
                 OutputStream out = response.getOutputStream()) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
    
    // 模拟聊天应用中上传图片的接口
    @PostMapping("/upload")
    public String uploadImage(@RequestParam("file") String fileData) {
        // 简单的文件保存逻辑
        // ...实际保存文件代码...
        return "{\\"status\\":\\"success\\"}";
    }
}