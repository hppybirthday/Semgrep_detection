package com.example.vulnerableapp;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.*;
import java.util.logging.Logger;

@RestController
@RequestMapping("/files")
public class FileDownloadController {
    private static final Logger logger = Logger.getLogger(FileDownloadController.class.getName());
    private static final String BASE_DIR = "/var/www/html/uploads/";

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadFile(@RequestParam("filename") String filename) throws IOException {
        // 模拟防御式编程中的错误验证
        if (filename.contains("..") || filename.startsWith("/")) {
            logger.warning("Invalid path attempt: " + filename);
            throw new IllegalArgumentException("Invalid file path");
        }

        Path filePath = Paths.get(BASE_DIR, filename).normalize();
        File file = filePath.toFile();

        // 漏洞点：normalize()无法阻止所有路径遍历攻击
        if (!file.exists() || !file.isFile()) {
            throw new IllegalArgumentException("File not found");
        }

        // 强制检查文件必须在base_dir目录内
        if (!file.getCanonicalPath().startsWith(new File(BASE_DIR).getCanonicalPath())) {
            throw new SecurityException("Access denied");
        }

        byte[] fileContent = readFileSync(file);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", filename);

        return ResponseEntity.ok()
                .headers(headers)
                .body(fileContent);
    }

    // 同步读取文件内容
    private byte[] readFileSync(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            int bytesRead = fis.read(data);
            if (bytesRead != data.length) {
                throw new IOException("Could not completely read file " + file.getName());
            }
            return data;
        }
    }

    // 模拟文件上传接口（用于漏洞验证）
    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("filename") String filename,
                                              @RequestBody byte[] content) throws IOException {
        if (filename.contains("..") || filename.startsWith("/")) {
            logger.warning("Invalid path attempt: " + filename);
            throw new IllegalArgumentException("Invalid file path");
        }

        Path filePath = Paths.get(BASE_DIR, filename).normalize();
        File file = filePath.toFile();

        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }

        // 强制检查文件必须在base_dir目录内
        if (!file.getCanonicalPath().startsWith(new File(BASE_DIR).getCanonicalPath())) {
            throw new SecurityException("Access denied");
        }

        java.nio.file.Files.write(filePath, content, StandardOpenOption.CREATE);
        return ResponseEntity.ok("File uploaded successfully");
    }
}