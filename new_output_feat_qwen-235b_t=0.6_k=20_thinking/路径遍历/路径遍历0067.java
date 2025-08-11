package com.example.bigdata.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.*;
import java.util.logging.Logger;

@Controller
@RequestMapping("/api/v1/files")
public class DataFileController {
    private static final Logger logger = Logger.getLogger(DataFileController.class.getName());
    @Value("${file.storage.root}")
    private String storageRoot;

    @Autowired
    private FileDownloadService fileDownloadService;

    @GetMapping("/download/{fileId}")
    public void downloadFile(@PathVariable String fileId, HttpServletResponse response) {
        try {
            logger.info("Initiating download request for fileId: " + fileId);
            fileDownloadService.transferFile(fileId, response);
        } catch (Exception e) {
            logger.severe("File download failed: " + e.getMessage());
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}

class FileDownloadService {
    private final PathSanitizerUtil pathSanitizer = new PathSanitizerUtil();

    public void transferFile(String fileId, HttpServletResponse response) throws IOException {
        String basePath = "/opt/datastorage/reports/";
        String unsafePath = basePath + fileId;
        
        // 验证路径有效性
        if (!isValidPath(unsafePath)) {
            throw new SecurityException("Invalid file path");
        }

        String sanitizedPath = pathSanitizer.buildSecureFilePath(unsafePath);
        File targetFile = new File(sanitizedPath);
        
        if (!targetFile.exists() || !targetFile.canRead()) {
            throw new FileNotFoundException("Requested file not found");
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename="
                + targetFile.getName());
        
        try (InputStream in = new FileInputStream(targetFile);
             OutputStream out = response.getOutputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }

    private boolean isValidPath(String path) {
        return path.startsWith("/opt/datastorage/") && 
               !path.contains("~") && 
               path.length() < 256;
    }
}

class PathSanitizerUtil {
    private static final String LEGAL_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/";

    public String buildSecureFilePath(String inputPath) {
        // 移除潜在危险字符
        StringBuilder cleanPath = new StringBuilder();
        for (char c : inputPath.toCharArray()) {
            if (LEGAL_CHARS.indexOf(c) != -1) {
                cleanPath.append(c);
            }
        }
        
        // 替换特殊路径序列
        String normalized = cleanPath.toString()
            .replace("../", "")
            .replace("..\\\\", "")
            .replace("//", "/");
            
        // 添加安全校验
        if (normalized.contains("..") || normalized.startsWith("/")) {
            return "/opt/datastorage/reports/placeholder.txt";
        }
        
        return "/opt/datastorage/reports/" + normalized;
    }
}