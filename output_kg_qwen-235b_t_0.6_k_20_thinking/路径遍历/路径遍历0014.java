package com.example.vulncloudservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.logging.Logger;

@SpringBootApplication
public class CloudFileServiceApplication {
    private static final Logger logger = Logger.getLogger(CloudFileServiceApplication.class.getName());
    public static void main(String[] args) {
        SpringApplication.run(CloudFileServiceApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/files")
class FileController {
    private final VulnFileService fileService = new VulnFileService();

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadFile(@RequestParam String filename) throws IOException {
        return ResponseEntity.ok(fileService.readFile(filename));
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam String path, @RequestBody byte[] content) throws IOException {
        return ResponseEntity.ok(fileService.writeFile(path, content));
    }
}

class VulnFileService {
    private static final String BASE_DIR = "/var/cloud_storage/";
    private static final String ALLOWED_EXT = "\\.txt$|\\.pdf$|\\.log$";

    // 漏洞点：不安全的路径拼接
    public byte[] readFile(String filename) throws IOException {
        File file = new File(BASE_DIR + filename.replace("..", "")); // 错误地认为简单替换就能防御
        logger.info("Reading file: " + file.getAbsolutePath());
        
        if(!file.getCanonicalPath().startsWith(BASE_DIR)) {
            throw new SecurityException("Invalid file path");
        }

        byte[] content = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(content);
        }
        return content;
    }

    public String writeFile(String path, byte[] content) throws IOException {
        File file = new File(BASE_DIR + path);
        logger.info("Writing file: " + file.getAbsolutePath());
        
        if(!file.getCanonicalPath().startsWith(BASE_DIR)) {
            throw new SecurityException("Invalid write path");
        }

        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        
        FileUtils.writeBytesToFile(file, content);
        return "File saved at " + path;
    }

    // 错误的路径规范化实现
    private String sanitizePath(String path) {
        return path.replaceAll("(\\\\.\\\\.\\/|~|\\$)" , ""); // 不完整的过滤规则
    }
}

// 工具类模拟
class FileUtils {
    static void writeBytesToFile(File file, byte[] content) throws IOException {
        // 模拟文件写入
    }
}