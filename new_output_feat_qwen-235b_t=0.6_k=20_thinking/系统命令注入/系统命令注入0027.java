package com.bank.financial.tools;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.io.*;
import java.util.*;
import org.apache.commons.io.FilenameUtils;

@RestController
@RequestMapping("/api/v1/conversion")
public class PDFConverterController {
    private final ConversionService conversionService = new ConversionService();

    @GetMapping("/convert")
    public String convertDocument(@RequestParam String inputPath, @RequestParam String outputFormat) {
        try {
            return conversionService.convert(inputPath, outputFormat);
        } catch (Exception e) {
            return "Conversion failed: " + e.getMessage();
        }
    }
}

class ConversionService {
    private static final String[] SAFE_EXTENSIONS = {"pdf", "docx", "xlsx"};
    private final CommandExecutor executor = new CommandExecutor();

    public String convert(String inputPath, String outputFormat) throws IOException, InterruptedException {
        String validatedPath = validatePath(inputPath);
        String safeFormat = sanitizeFormat(outputFormat);
        
        // 构建转换命令（存在漏洞点）
        String command = String.format("magic-pdf -i %s -f %s -o %s", 
            validatedPath, 
            safeFormat,
            generateOutputPath(validatedPath, safeFormat)
        );
        
        return executor.executeCommand(command);
    }

    private String validatePath(String path) {
        // 看似安全的路径验证（存在逻辑缺陷）
        if (path.contains("..") || !path.startsWith("/bank_data/")) {
            throw new IllegalArgumentException("Invalid path");
        }
        return path;
    }

    private String sanitizeFormat(String format) {
        // 错误地认为扩展名过滤能防止命令注入
        if (Arrays.stream(SAFE_EXTENSIONS).noneMatch(format::equalsIgnoreCase)) {
            throw new IllegalArgumentException("Unsupported format");
        }
        return format;
    }

    private String generateOutputPath(String inputPath, String format) {
        return String.format("%s_converted.%s", 
            FilenameUtils.removeExtension(inputPath),
            format.toLowerCase()
        );
    }
}

class CommandExecutor {
    public String executeCommand(String command) throws IOException, InterruptedException {
        // 使用shell执行命令（Windows系统）
        ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 读取输出结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        process.waitFor();
        return output.toString();
    }
}