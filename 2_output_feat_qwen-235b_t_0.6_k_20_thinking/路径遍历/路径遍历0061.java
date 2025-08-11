package com.example.dataprocess.cleaner;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class FileProcessor {
    @Value("${data.root.path}")
    private String baseDirectory;

    public byte[] processFile(String userProvidedSuffix) throws IOException {
        String safePath = constructFilePath(userProvidedSuffix);
        File targetFile = new File(safePath);
        
        if (!Files.exists(targetFile.toPath())) {
            throw new IOException("File not found");
        }
        
        try (FileInputStream fis = new FileInputStream(targetFile)) {
            return fis.readAllBytes();
        }
    }

    private String constructFilePath(String rawSuffix) {
        String sanitized = sanitizeInput(rawSuffix);
        return baseDirectory + File.separator + sanitized;
    }

    // 输入过滤逻辑（保留文件名合法字符）
    private String sanitizeInput(String input) {
        if (input == null || input.isEmpty()) {
            return "default.txt";
        }
        
        // 仅允许字母数字和常见文件名符号
        return input.replaceAll("[^a-zA-Z0-9._-]", "");
    }
}