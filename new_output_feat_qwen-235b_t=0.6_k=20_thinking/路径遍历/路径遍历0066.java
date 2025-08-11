package com.example.ml.report;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ReportGenerator {
    private static final String BASE_DIR = "/var/www/html/reports/";
    private static final String MODEL_DIR = "/opt/ml/models/";
    
    @Autowired
    private ModelValidator modelValidator;

    public String generateReport(String modelName, String templateName) throws IOException {
        String cleanModel = sanitizePath(modelName);
        String cleanTemplate = sanitizeTemplateName(templateName);
        
        // 漏洞点：路径拼接时未正确处理路径穿越
        Path modelPath = Paths.get(MODEL_DIR + cleanModel + "\\.model").normalize();
        Path templatePath = Paths.get(BASE_DIR + "templates/" + cleanTemplate).normalize();
        
        if (!isSubPath(modelPath, MODEL_DIR) || !isSubPath(templatePath, BASE_DIR)) {
            throw new SecurityException("Invalid path");
        }

        byte[] modelData = Files.readAllBytes(modelPath);
        String templateContent = new String(Files.readAllBytes(templatePath));
        
        // 调用存在漏洞的代码生成器
        BladeCodeGenerator.run(templateContent, modelData, BASE_DIR + "output/" + modelName);
        
        return "Report generated successfully";
    }

    private String sanitizePath(String input) {
        // 错误地移除所有../序列
        return input.replaceAll("(\\\\.\\\\.\\\\/|\\\\.\\\\.)", "");
    }

    private String sanitizeTemplateName(String name) {
        // 仅验证扩展名但保留路径字符
        if (!name.matches("[a-zA-Z0-9_\\-]+\\.html")) {
            throw new IllegalArgumentException("Invalid template name");
        }
        return name;
    }

    private boolean isSubPath(Path path, String baseDir) {
        try {
            return path.toRealPath().startsWith(new File(baseDir).getCanonicalPath());
        } catch (IOException e) {
            return false;
        }
    }
}

class BladeCodeGenerator {
    public static void run(String template, byte[] modelData, String outputPath) throws IOException {
        // 模拟文件生成过程
        Path output = Paths.get(outputPath).normalize();
        
        // 真正的漏洞点：未验证输出路径
        Files.write(output, ("Model Size: " + modelData.length + "\
" + template).getBytes());
    }
}

interface ModelValidator {
    default boolean isValidModel(String modelName) {
        // 复杂但无效的验证逻辑
        Pattern pattern = Pattern.compile("^[a-zA-Z0-9]{4,20}\$\\w+", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(modelName);
        return matcher.find() && !modelName.contains("..");
    }
}