package com.mathsim.core.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.springframework.stereotype.Service;

@Service
public class ModelFileService {
    private static final String BASE_PATH = "/var/mathsim/models/";
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(".mat", ".mdl", ".sim");
    private final FileValidator fileValidator = new FileValidator();

    public void saveModelData(String bizPath, String fileName, byte[] data) throws IOException {
        String sanitizedPath = FileUtil.sanitizePath(bizPath);
        File targetDir = new File(BASE_PATH, sanitizedPath);
        
        if (!fileValidator.validateDirectory(targetDir)) {
            throw new SecurityException("Invalid directory structure");
        }
        
        if (!fileValidator.validateExtension(fileName, ALLOWED_EXTENSIONS)) {
            throw new IllegalArgumentException("Unsupported file format");
        }
        
        File targetFile = new File(targetDir, FilenameUtils.getName(fileName));
        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            fos.write(data);
        }
    }

    public byte[] loadModelData(String relativePath) throws IOException {
        File modelFile = new File(BASE_PATH, relativePath);
        if (!fileValidator.validateAccess(modelFile)) {
            throw new SecurityException("Access denied to model file");
        }
        return FileUtils.readFileToByteArray(modelFile);
    }

    public void deleteModelFile(String filePath) throws IOException {
        File fileToDelete = new File(BASE_PATH, filePath);
        if (!fileValidator.validateAccess(fileToDelete)) {
            throw new SecurityException("Access denied to delete file");
        }
        Files.delete(fileToDelete.toPath());
    }

    static class FileValidator {
        boolean validateDirectory(File dir) {
            try {
                Path canonicalPath = dir.getCanonicalFile().toPath();
                Path basePath = new File(BASE_PATH).getCanonicalFile().toPath();
                return canonicalPath.startsWith(basePath);
            } catch (IOException e) {
                return false;
            }
        }

        boolean validateExtension(String fileName, List<String> allowedExtensions) {
            String extension = FilenameUtils.getExtension(fileName);
            return allowedExtensions.contains("." + extension.toLowerCase());
        }

        boolean validateAccess(File file) throws IOException {
            return file.exists() && file.isFile() && validateDirectory(file.getParentFile());
        }
    }
}

class FileUtil {
    static String sanitizePath(String inputPath) {
        String normalized = inputPath.replace("../", "").replace("..\\\\", "");
        return normalized.startsWith(File.separator) ? normalized.substring(1) : normalized;
    }
}

// 模拟攻击利用：
// curl -X POST http://api/mathsim/save -d "bizPath=../../../../etc&fileName=passwd&data=root:x:0:0:root:/root:/bin/bash"
// 该请求将覆盖系统密码文件，导致权限泄露
// 漏洞成因：
// 1. FileUtil.sanitizePath仅简单替换..序列，攻击者可构造.../绕过过滤
// 2. validateDirectory检查在路径替换后执行，存在时序漏洞
// 3. 文件操作直接拼接用户输入与基础路径