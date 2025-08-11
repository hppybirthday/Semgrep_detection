package com.crm.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;

@SpringBootApplication
public class CrmApplication {

    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }

    @RestController
    @RequestMapping("/api/files")
    public class FileController {
        
        // 模拟CRM系统中的客户文件存储目录
        private final String BASE_DIR = "/var/crm/customer_docs/";

        @GetMapping("/download")
        public ResponseEntity<byte[]> downloadFile(@RequestParam String filename) throws IOException {
            
            // 漏洞点：直接拼接用户输入的文件名
            File file = new File(BASE_DIR + filename);
            
            if (!file.exists()) {
                throw new RuntimeException("File not found");
            }

            // 读取文件内容
            FileInputStream fileInputStream = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fileInputStream.read(data);
            fileInputStream.close();

            // 构建响应头
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentDispositionFormData("attachment", filename);
            
            return ResponseEntity.ok().headers(headers).body(data);
        }
        
        @PostMapping("/upload")
        public String uploadFile(@RequestParam String filename, @RequestBody byte[] content) throws IOException {
            File file = new File(BASE_DIR + filename);
            Files.write(file.toPath(), content);
            return "File uploaded successfully";
        }
    }
}