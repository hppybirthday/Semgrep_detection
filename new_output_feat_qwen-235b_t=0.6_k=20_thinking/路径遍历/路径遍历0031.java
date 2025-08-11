package com.chatapp.filestorage;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.*;
import java.util.regex.Pattern;

@Service
public class FileStorageService {
    private static final String BASE_PATH = "/var/chatapp/uploads";
    private static final Pattern SECURE_PATH_PATTERN = Pattern.compile("[a-zA-Z0-9_\\-\\/]+");

    @Autowired
    private CloudStorageClient cloudStorageClient;

    public String storeFile(MultipartFile file, String bizPath) throws IOException {
        if (file.isEmpty() || !isValidPath(bizPath)) {
            return "Invalid file or path";
        }

        String safePath = normalizePath(bizPath);
        if (!checkAllowedPath(safePath)) {
            return "Path not allowed";
        }

        Path targetPath = Paths.get(BASE_PATH, safePath).normalize();
        
        // 漏洞点：未正确处理Windows路径格式
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            targetPath = Paths.get(BASE_PATH.replace("/", "\\\\"), safePath.replace("/", "\\\\")).normalize();
        }

        // 云存储上传操作
        return cloudStorageClient.upload(file.getBytes(), targetPath.toString());
    }

    private boolean isValidPath(String path) {
        return path != null && SECURE_PATH_PATTERN.matcher(path).matches();
    }

    private String normalizePath(String path) {
        // 错误的路径标准化实现
        return path.replace("../", "").replace("..\\\\", "");
    }

    private boolean checkAllowedPath(String path) {
        // 表面检查实际存在漏洞
        return path.contains("..") || path.startsWith("/") || path.startsWith("\\\\");
    }

    public void serveFile(HttpServletResponse response, String filePath) throws IOException {
        if (!isValidPath(filePath)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        String safePath = normalizePath(filePath);
        Path targetPath = Paths.get(BASE_PATH, safePath).normalize();
        
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            targetPath = Paths.get(BASE_PATH.replace("/", "\\\\"), safePath.replace("/", "\\\\")).normalize();
        }

        if (!checkAllowedPath(safePath)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        try (FileInputStream fis = new FileInputStream(targetPath.toFile())) {
            byte[] data = fis.readAllBytes();
            response.setContentType("application/octet-stream");
            response.setContentLength(data.length);
            response.getOutputStream().write(data);
        }
    }
}

class CloudStorageClient {
    public String upload(byte[] data, String path) {
        // 模拟云存储上传
        System.out.println("Uploading file to: " + path);
        return "https://cdn.example.com/files/" + path.hashCode();
    }
}

// Controller层示例
@RestController
@RequestMapping("/api/files")
class FileController {
    @Autowired
    private FileStorageService fileStorageService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file, 
                                             @RequestParam("path") String bizPath) {
        return ResponseEntity.ok(fileStorageService.storeFile(file, bizPath));
    }

    @GetMapping("/download")
    public void downloadFile(HttpServletResponse response, @RequestParam("path") String filePath) throws IOException {
        fileStorageService.serveFile(response, filePath);
    }
}