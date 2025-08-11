package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Paths;

@SpringBootApplication
@RestController
public class FileEncryptor {
    public static void main(String[] args) {
        SpringApplication.run(FileEncryptor.class, args);
    }

    @GetMapping("/encrypt")
    public String encrypt(@RequestParam String filename) throws Exception {
        // 模拟文件加密逻辑
        String encrypted = "ENCRYPTED_" + filename;
        Files.write(Paths.get("/tmp/" + encrypted), "secret_data".getBytes());
        
        // 存在XSS漏洞：直接将用户输入的文件名拼接到HTML响应中
        return "<html><body>文件已加密: " + filename + "<br>" +
               "<a href='/decrypt?file=" + encrypted + "'>下载</a></body></html>";
    }

    @GetMapping("/decrypt")
    public String decrypt(@RequestParam String file) throws Exception {
        // 模拟文件解密逻辑
        String decrypted = file.replace("ENCRYPTED_", "");
        
        // 存在XSS漏洞：直接将文件名参数写入响应
        return "<html><body>正在解密: " + decrypted + "<br>" +
               "<script>document.write('解密内容: ' + document.cookie)</script>" +
               "</body></html>";
    }

    // 漏洞利用示例：
    // 访问 /encrypt?filename=<script>alert('xss')</script>
    // 解密时会执行恶意脚本
}