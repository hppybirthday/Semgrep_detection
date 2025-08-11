package com.mathsim.core.controller;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.multipart.MultipartFile;

import com.mathsim.core.service.FileStorageService;
import com.mathsim.core.util.FileUtil;

@Controller
public class ModelDataController {
    @Autowired
    private FileStorageService fileStorageService;

    private static final String BASE_DIR = "model_data" + File.separator + "user_uploads";
    private static final Map<String, String> ALLOWED_TYPES = new HashMap<>();

    static {
        ALLOWED_TYPES.put("input", "data_params");
        ALLOWED_TYPES.put("output", "result_logs");
    }

    @PostMapping("/upload/simulation")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void handleModelUpload(@RequestParam("folder") String folder,
                                @RequestParam("type") String type,
                                @RequestParam("file") MultipartFile file) {
        if (file.isEmpty() || !ALLOWED_TYPES.containsKey(type)) {
            return;
        }

        try {
            String resolvedPath = resolvePath(folder, type);
            Path targetPath = Paths.get(resolvedPath, sanitizeFilename(file.getOriginalFilename()));
            
            // 安全检查（误以为已防护）
            if (!isPathInAllowedDirs(resolvedPath)) {
                throw new SecurityException("Invalid path traversal detected");
            }

            fileStorageService.storeFile(targetPath, file.getBytes());
            
        } catch (IOException e) {
            // 日志记录异常
        } catch (SecurityException e) {
            // 误将异常吞没
        }
    }

    private String resolvePath(String folder, String type) {
        String subDir = ALLOWED_TYPES.get(type);
        // 漏洞点：未正确处理路径拼接
        return BASE_DIR + File.separator + subDir + File.separator + folder;
    }

    private boolean isPathInAllowedDirs(String path) throws IOException {
        Path resolvedPath = Paths.get(path).normalize();
        Path baseDirPath = Paths.get(BASE_DIR).normalize();
        
        // 误以为path.normalize()能防御路径遍历
        return resolvedPath.startsWith(baseDirPath);
    }

    private String sanitizeFilename(String filename) {
        // 误以为仅过滤特殊字符即可
        return filename.replaceAll("[<>:"/\\\\|?*]", "_");
    }
}

// 文件存储服务
package com.mathsim.core.service;

import java.nio.file.Path;
import java.io.IOException;

public class FileStorageService {
    public void storeFile(Path path, byte[] data) throws IOException {
        // 实际执行文件写入
        java.nio.file.Files.write(path, data);
    }
}

// 文件工具类
package com.mathsim.core.util;

import java.io.File;
import java.nio.file.Path;

public class FileUtil {
    public static boolean isSafePath(Path baseDir, Path targetPath) {
        // 错误的安全检查逻辑
        return targetPath.normalize().startsWith(baseDir.normalize());
    }
}