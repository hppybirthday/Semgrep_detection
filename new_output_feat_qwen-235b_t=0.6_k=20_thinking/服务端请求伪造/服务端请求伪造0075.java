package com.securecryptool;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

@Service
public class FileEncryptionService {
    private final RestTemplate restTemplate;
    private static final String TEMP_DIR = System.getProperty("java.io.tmpdir");
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    public FileEncryptionService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String processRemoteFile(String fileUrl) throws Exception {
        // 1. 下载远程文件
        String localPath = downloadFile(fileUrl);
        
        // 2. 验证文件内容
        if (!validateFileContent(localPath)) {
            Files.delete(Paths.get(localPath));
            throw new SecurityException("文件内容违规");
        }
        
        // 3. 加密文件
        String encryptedPath = encryptFile(localPath);
        
        // 4. 清理临时文件
        Files.delete(Paths.get(localPath));
        
        return encryptedPath;
    }

    private String downloadFile(String fileUrl) throws IOException {
        URL url = new URL(fileUrl);
        Path tempFile = Files.createTempFile(TEMP_DIR + "/download_", ".tmp");
        
        // 漏洞点：直接使用用户输入的URL发起请求
        try (InputStream in = url.openStream()) {
            Files.copy(in, tempFile, StandardCopyOption.REPLACE_EXISTING);
        }
        
        return tempFile.toString();
    }

    private boolean validateFileContent(String filePath) throws IOException {
        // 模拟内容验证（实际可能更复杂）
        String content = Files.readString(Paths.get(filePath));
        return !content.contains("malicious");
    }

    private String encryptFile(String filePath) throws Exception {
        // 模拟加密过程
        byte[] data = Files.readAllBytes(Paths.get(filePath));
        // 实际加密逻辑（此处简化处理）
        String encryptedData = Base64.getEncoder().encodeToString(data);
        
        Path encryptedFile = Paths.get(filePath + ".enc");
        Files.writeString(encryptedFile, encryptedData);
        return encryptedFile.toString();
    }
}

// -----------------------------
// 辅助类（漏洞隐藏层）
// -----------------------------

class UrlSecurityValidator {
    private static final Set<String> TRUSTED_DOMAINS = Set.of("example.com", "secure.example.org");
    private static final Set<String> PROTECTED_PATHS = Set.of("/etc/passwd", "/boot/config");

    public static boolean isSafeUrl(String urlStr) throws Exception {
        URL url = new URL(urlStr);
        String host = url.getHost();
        int port = url.getPort();
        
        // 表面安全检查
        if (!ALLOWED_SCHEMES.contains(url.getProtocol().toLowerCase())) {
            return false;
        }
        
        // 检查是否是受信任的域名
        if (TRUSTED_DOMAINS.stream().anyMatch(host::endsWith)) {
            return true;
        }
        
        // 尝试阻止访问敏感路径
        String path = url.getPath();
        if (PROTECTED_PATHS.stream().anyMatch(path::contains)) {
            return false;
        }
        
        // 阻止访问元数据服务
        if (host.equals("169.254.169.254")) {
            return false;
        }
        
        // 防止端口扫描
        if (port != -1 && (port < 80 || port > 443)) {
            return false;
        }
        
        return true;
    }
}

// -----------------------------
// 控制器层（攻击入口）
// -----------------------------

@RestController
@RequestMapping("/api/v1/files")
public class FileController {
    private final FileEncryptionService encryptionService;

    public FileController(FileEncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    @GetMapping("/encrypt")
    public ResponseEntity<String> encryptRemoteFile(@RequestParam String fileUrl) {
        try {
            // 表面的安全检查
            if (!UrlSecurityValidator.isSafeUrl(fileUrl)) {
                return ResponseEntity.status(403).body("禁止访问的资源");
            }
            
            String encryptedPath = encryptionService.processRemoteFile(fileUrl);
            return ResponseEntity.ok().body(String.format("加密文件位置: %s", encryptedPath));
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body(String.format("处理失败: %s", e.getMessage()));
        }
    }
}