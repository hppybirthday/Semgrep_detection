package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.*;

@SpringBootApplication
@RestController
public class PathTraversalDemo {

    // 模拟文件存储根目录
    private static final String BASE_DIR = "/var/www/html/";

    public static void main(String[] args) {
        SpringApplication.run(PathTraversalDemo.class, args);
    }

    @GetMapping("/download")
    public void downloadFile(@RequestParam("filename") String filename, HttpServletResponse response) {
        try {
            // 漏洞点：直接拼接用户输入构造文件路径
            Path filePath = Paths.get(BASE_DIR + filename);
            
            // 简单检查文件是否存在
            if (!Files.exists(filePath)) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
                return;
            }

            // 设置响应头
            response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
            response.setHeader("Content-Disposition", "attachment; filename=\\"" + filename + "\\"");

            // 文件传输
            try (InputStream in = new FileInputStream(filePath.toFile());
                 OutputStream out = response.getOutputStream()) {

                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }

        } catch (Exception e) {
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error processing request");
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    // 模拟初始化文件系统
    @GetMapping("/init")
    public String init() {
        try {
            // 创建测试文件
            Files.createDirectories(Paths.get(BASE_DIR));
            Files.write(Paths.get(BASE_DIR + "test.txt"), "This is a test file".getBytes());
            
            // 创建敏感文件（模拟攻击目标）
            Files.write(Paths.get("/tmp/secret.txt"), "SECRET_DATA".getBytes());
            
            return "System initialized";
        } catch (Exception e) {
            return "Init failed: " + e.getMessage();
        }
    }
}