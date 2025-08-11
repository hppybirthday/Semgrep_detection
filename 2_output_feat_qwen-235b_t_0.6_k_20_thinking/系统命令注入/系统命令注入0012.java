package com.corp.enterprise.document;

import org.apache.commons.io.FilenameUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Resource;
import java.io.File;
import java.io.IOException;

@Service
public class DocumentProcessingService {
    
    @Resource
    private FileStorageService fileStorage;
    
    @Resource
    private SecurityValidator securityValidator;
    
    /**
     * 处理文档上传并执行转换任务
     * @param file 上传的文档文件
     * @param s 转换参数
     * @return 转换结果
     * @throws IOException 文件处理异常
     */
    public ConversionResult processUpload(MultipartFile file, String s) throws IOException {
        // 存储上传文件
        File tempFile = fileStorage.storeTempFile(file);
        
        // 构建转换命令
        String command = buildConversionCommand(tempFile.getAbsolutePath(), s);
        
        // 执行文档转换
        ProcessResult result = executeConversionCommand(command);
        
        // 清理临时文件
        fileStorage.cleanupTempFile(tempFile);
        
        return new ConversionResult(result.getOutput(), result.getExitCode());
    }
    
    /**
     * 构建文档转换命令
     * @param filePath 文件路径
     * @param s 转换参数
     * @return 完整命令字符串
     */
    private String buildConversionCommand(String filePath, String s) {
        // 验证并清理参数
        String safeParam = securityValidator.sanitizeParam(s);
        
        // 构建转换命令
        return String.format("docx-convert --input %s --output /converted/%s-%d.docx --param '%s'", 
                filePath, 
                FilenameUtils.getBaseName(filePath),
                System.currentTimeMillis(),
                safeParam);
    }
    
    /**
     * 执行转换命令
     * @param command 完整命令
     * @return 执行结果
     */
    private ProcessResult executeConversionCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取执行输出
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
            }
            
            return new ProcessResult(output.toString(), process.exitValue());
            
        } catch (Exception e) {
            throw new RuntimeException("Command execution failed", e);
        }
    }
    
    /**
     * 转换结果封装类
     */
    public static class ConversionResult {
        private final String output;
        private final int exitCode;
        
        public ConversionResult(String output, int exitCode) {
            this.output = output;
            this.exitCode = exitCode;
        }
        
        // Getters omitted for brevity
    }
    
    /**
     * 进程执行结果封装
     */
    private static class ProcessResult {
        private final String output;
        private final int exitCode;
        
        public ProcessResult(String output, int exitCode) {
            this.output = output;
            this.exitCode = exitCode;
        }
    }
}