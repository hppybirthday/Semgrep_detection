package com.securetool.encryption;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/file")
public class FileUploadController {
    private final FileStorageService fileStorageService = new FileStorageService();

    @PostMapping(path = "/upload", consumes = "multipart/form-data")
    public Map<String, String> handleFileUpload(@RequestParam("prefix") String prefix,
                                               @RequestParam("suffix") String suffix,
                                               @RequestParam("file") MultipartFile file) {
        Map<String, String> response = new HashMap<>();
        try {
            // 执行文件存储操作
            fileStorageService.storeFile(prefix, suffix, file.getBytes(), file.getOriginalFilename());
            response.put("status", "success");
        } catch (IOException e) {
            response.put("status", "failed");
            response.put("error", e.getMessage());
        }
        return response;
    }
}

class FileStorageService {
    private static final Path BASE_PATH = Paths.get("/var/secure_storage");
    private final FileUtil fileUtil = new FileUtil();

    void storeFile(String prefix, String suffix, byte[] data, String originalFilename) throws IOException {
        // 构建存储路径结构
        Path targetDir = buildStoragePath(prefix, suffix);
        
        // 验证路径合法性
        if (!isValidPath(targetDir)) {
            throw new SecurityException("Invalid path configuration");
        }

        // 确保目录存在
        if (!Files.exists(targetDir)) {
            Files.createDirectories(targetDir);
        }

        // 执行文件存储
        fileUtil.writeToFile(data, targetDir.resolve(originalFilename));
    }

    private Path buildStoragePath(String prefix, String suffix) {
        // 将用户输入拼接到基础路径中
        return BASE_PATH.resolve(prefix).resolve(suffix);
    }

    private boolean isValidPath(Path path) throws IOException {
        // 验证路径是否在允许的目录范围内
        Path realPath = path.toRealPath();
        return realPath.startsWith(BASE_PATH.toRealPath());
    }
}

class FileUtil {
    void writeToFile(byte[] data, Path filePath) throws IOException {
        // 创建父目录（如果需要）
        if (Files.exists(filePath)) {
            Files.delete(filePath);
        }
        
        // 写入文件内容
        Files.write(filePath, data, StandardOpenOption.CREATE_NEW);
    }
}