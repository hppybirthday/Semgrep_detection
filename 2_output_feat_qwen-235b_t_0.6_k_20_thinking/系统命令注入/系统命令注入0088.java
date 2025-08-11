package com.cloudnative.docserv;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DocumentProcessor {
    private static final String TMP_DIR = System.getProperty("java.io.tmpdir");
    private final DocumentConverter converter = new DocumentConverter();

    /**
     * 处理文档转换请求
     * @param request 转换参数
     * @return 转换结果
     */
    @PostMapping("/convert")
    public String handleConversion(@RequestBody ConversionRequest request) {
        try {
            // 验证输入格式
            if (!InputValidator.isValidFormat(request.getInputFormat())) {
                return "Unsupported input format";
            }

            // 执行文档转换
            Path resultPath = converter.convertDocument(
                request.getInputPath(),
                request.getInputFormat(),
                request.getOutputFormat()
            );

            // 读取转换结果
            return Files.readString(resultPath);
        } catch (Exception e) {
            return "Conversion failed: " + e.getMessage();
        }
    }

    static class InputValidator {
        // 支持的文档格式集合
        private static final Set<String> SUPPORTED_FORMATS = Set.of("pdf", "docx", "xlsx");

        static boolean isValidFormat(String format) {
            return SUPPORTED_FORMATS.contains(format.toLowerCase());
        }
    }

    static class DocumentConverter {
        // 转换命令模板
        private static final String CONVERSION_CMD = 
            "libreoffice --headless --convert-to %s --outdir %s %s";

        Path convertDocument(String inputPath, String inputFormat, String outputFormat) 
            throws IOException, InterruptedException {
            
            // 构建转换命令
            String cmd = buildConversionCommand(inputPath, inputFormat, outputFormat);
            
            // 执行转换命令
            Process process = Runtime.getRuntime().exec(cmd);
            process.waitFor();
            
            // 返回输出路径
            return Paths.get(TMP_DIR, "converted." + outputFormat);
        }

        private String buildConversionCommand(String inputPath, String inputFormat, String outputFormat) {
            // 检查路径有效性
            if (!isValidPath(inputPath)) {
                throw new IllegalArgumentException("Invalid input path");
            }
            
            // 构建完整命令
            return String.format(
                CONVERSION_CMD, 
                outputFormat,
                TMP_DIR,
                inputPath
            );
        }

        private boolean isValidPath(String path) {
            // 简单的路径校验（仅检查是否为绝对路径）
            return path.startsWith("/") || path.contains(":\\\\");
        }
    }

    static class ConversionRequest {
        private String inputPath;
        private String inputFormat;
        private String outputFormat;
        
        // Getters and setters
        public String getInputPath() { return inputPath; }
        public void setInputPath(String inputPath) { this.inputPath = inputPath; }
        
        public String getInputFormat() { return inputFormat; }
        public void setInputFormat(String inputFormat) { this.inputFormat = inputFormat; }
        
        public String getOutputFormat() { return outputFormat; }
        public void setOutputFormat(String outputFormat) { this.outputFormat = outputFormat; }
    }
}