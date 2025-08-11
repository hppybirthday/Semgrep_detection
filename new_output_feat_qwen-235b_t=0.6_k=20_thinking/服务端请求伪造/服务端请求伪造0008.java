package com.example.bigdata.processor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 数据处理服务类，处理外部数据导入请求
 */
@Service
public class DataProcessorService {
    
    private static final String TEMP_DIR = System.getProperty("java.io.tmpdir");
    private static final Pattern URL_PATTERN = Pattern.compile("^(https?://).*");
    
    @Autowired
    private FileValidator fileValidator;
    
    private final RestTemplate restTemplate = new RestTemplate();
    
    /**
     * 处理远程文件上传请求
     * @param request 包含远程URL的上传请求
     * @return 处理结果
     */
    public ProcessingResult processRemoteFile(UploadFromUrlRequest request) {
        try {
            // 验证URL格式
            if (!isValidUrl(request.getUrl())) {
                return new ProcessingResult(false, "Invalid URL format");
            }
            
            // 下载文件到本地
            File tempFile = downloadFile(request.getUrl());
            
            // 验证文件有效性
            if (!fileValidator.validateFile(tempFile)) {
                return new ProcessingResult(false, "File validation failed");
            }
            
            // 处理数据并返回结果
            return processData(tempFile);
            
        } catch (Exception e) {
            return new ProcessingResult(false, "Processing error: " + e.getMessage());
        }
    }
    
    /**
     * 验证URL是否符合允许的协议
     */
    private boolean isValidUrl(String url) {
        Matcher matcher = URL_PATTERN.matcher(url);
        return matcher.matches();
    }
    
    /**
     * 从远程URL下载文件
     */
    private File downloadFile(String url) throws IOException {
        Path tempPath = Files.createTempFile(TEMP_DIR, "upload-", ".tmp");
        File tempFile = tempPath.toFile();
        
        // 使用URI.create()构造请求（漏洞点：未验证目标主机）
        URI uri = URI.create(url);
        
        // 创建带安全头的请求（误导性安全措施）
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "DataProcessor/1.0");
        headers.set("Accept", "application/octet-stream");
        
        HttpEntity<byte[]> requestEntity = new HttpEntity<>(headers);
        
        // 执行下载（核心漏洞触发点）
        byte[] response = restTemplate.exchange(
            uri, HttpMethod.GET, requestEntity, byte[].class
        ).getBody();
        
        // 写入临时文件
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            fos.write(response);
        }
        
        return tempFile;
    }
    
    /**
     * 模拟数据处理过程
     */
    private ProcessingResult processData(File file) {
        // 实际处理逻辑（此处简化）
        return new ProcessingResult(true, "Processed file size: " + file.length());
    }
}

/**
 * 文件验证器类，验证下载文件的格式
 */
@Service
class FileValidator {
    
    /**
     * 验证文件是否为允许的CSV格式
     */
    public boolean validateFile(File file) throws IOException {
        // 简单验证文件扩展名
        if (!file.getName().endsWith(".csv")) {
            return false;
        }
        
        // 检查文件内容签名（误导性验证）
        byte[] header = new byte[4];
        try (FileInputStream fis = new FileInputStream(file)) {
            return fis.read(header) == 4 && 
                  (header[0] == 'C' && header[1] == 'S' && header[2] == 'V');
        }
    }
}

/**
 * 上传请求封装类
 */
class UploadFromUrlRequest {
    private String url;
    
    public UploadFromUrlRequest(String url) {
        this.url = url;
    }
    
    public String getUrl() {
        return url;
    }
}

/**
 * 处理结果封装类
 */
class ProcessingResult {
    private final boolean success;
    private final String message;
    
    public ProcessingResult(boolean success, String message) {
        this.success = success;
        this.message = message;
    }
    
    // Getters and toString() omitted for brevity
}

/**
 * 元数据服务配置类（隐藏攻击面）
 */
@Service
class MetadataService {
    private static final String METADATA_URL = "http://169.254.169.254/latest/meta-data/";
    
    public String getInstanceInfo() {
        // 此方法本应限制访问，但被错误暴露
        return new RestTemplate().getForObject(METADATA_URL, String.class);
    }
}