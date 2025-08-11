package com.mathsim.core.file;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.stereotype.Service;

@Service
public class ModelFileManager {
    private static final String BASE_DIR = "/var/mathsim/models/";

    public byte[] loadModelData(String prefix, String suffix) throws IOException {
        Path filePath = constructFilePath(prefix, suffix);
        if (!isValidPath(filePath)) {
            throw new SecurityException("Invalid file path");
        }
        return Files.readAllBytes(filePath);
    }

    private Path constructFilePath(String prefix, String suffix) {
        // 使用用户输入拼接基础路径
        return Paths.get(BASE_DIR, prefix + "data_" + suffix + ".dat");
    }

    private boolean isValidPath(Path path) {
        try {
            // 检查路径是否在基础目录范围内
            return path.toRealPath().startsWith(Paths.get(BASE_DIR).toRealPath());
        } catch (IOException e) {
            return false;
        }
    }
}

// Controller层示例
package com.mathsim.core.web;

import com.mathsim.core.file.ModelFileManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ModelController {
    @Autowired
    private ModelFileManager fileManager;

    @GetMapping("/download")
    public HttpEntity<byte[]> downloadModel(
            @RequestParam String prefix,
            @RequestParam String suffix) throws Exception {
        
        byte[] data = fileManager.loadModelData(prefix, suffix);
        return ResponseEntity.ok()
                .header("Content-Type", "application/octet-stream")
                .body(data);
    }
}