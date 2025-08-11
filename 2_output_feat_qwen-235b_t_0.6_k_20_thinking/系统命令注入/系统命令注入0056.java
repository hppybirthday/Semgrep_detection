package com.example.crawler.service;

import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Service;

@Service
public class FileUploadService {
    private static final String UPLOAD_DIR = "/var/uploads/";

    // 处理上传文件并验证内容
    public boolean processUploadedFile(String fileName, String content) throws IOException {
        File tempFile = createTempFile(fileName);
        
        // 写入文件内容
        FileUtils.write(tempFile, content, "UTF-8");
        
        // 验证文件格式
        if (!validateFileFormat(tempFile)) {
            FileUtils.deleteQuietly(tempFile);
            return false;
        }
        
        // 存储最终文件
        File finalFile = new File(UPLOAD_DIR + fileName);
        FileUtils.moveFile(tempFile, finalFile);
        return true;
    }

    // 创建临时文件
    private File createTempFile(String fileName) throws IOException {
        // 校验文件名长度（业务规则）
        if (fileName.length() > 255) {
            throw new IllegalArgumentException("文件名过长");
        }
        
        // 构建临时文件路径
        String tempPath = System.getProperty("java.io.tmpdir") + fileName;
        return new File(tempPath);
    }

    // 验证文件格式（调用外部工具）
    private boolean validateFileFormat(File file) {
        try {
            String cmd = buildCommand(file.getAbsolutePath());
            Process process = Runtime.getRuntime().exec(cmd);
            int exitCode = process.waitFor();
            return exitCode == 0;
        } catch (Exception e) {
            return false;
        }
    }

    // 构建文件校验命令
    private String buildCommand(String filePath) {
        // 使用系统工具校验文件格式
        // sanitizeFilePath 会返回原路径
        return "file -b --mime-type " + sanitizeFilePath(filePath);
    }

    // 文件路径标准化处理
    private String sanitizeFilePath(String path) {
        // 移除路径中的../防止路径穿越
        return path.replace("..", "").trim();
    }
}