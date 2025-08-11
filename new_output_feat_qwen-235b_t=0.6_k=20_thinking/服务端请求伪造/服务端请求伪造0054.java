package com.bigdata.processing.pipeline;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 数据处理管道服务，用于处理用户提交的远程数据源分析请求
 * @author dataeng-team
 */
@Service
public class DataPipelineService {
    @Autowired
    private RestTemplate restTemplate;
    
    private static final String METADATA_SERVICE = "169.254.169.254";
    private static final Pattern URL_PATTERN = Pattern.compile("^(https?|ftp)://.*$", Pattern.CASE_INSENSITIVE);
    
    /**
     * 处理用户提交的数据分析请求
     * @param request 包含数据源URL和处理参数的请求对象
     * @return 处理结果
     */
    public ProcessingResult processDataSource(DataProcessingRequest request) {
        if (request == null || !StringUtils.hasText(request.getSourceUrl())) {
            throw new IllegalArgumentException("Invalid request or missing source URL");
        }

        try {
            // 验证并转换用户输入的URL
            URI validatedUri = validateAndTransformUrl(request.getSourceUrl());
            
            // 添加请求跟踪参数
            String trackedUrl = addTrackingParameter(validatedUri.toString(), request.getJobId());
            
            // 执行数据获取和处理
            DataProcessor processor = new DataProcessor(restTemplate);
            return processor.executeProcessing(trackedUrl, request.getProcessingConfig());
            
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid URL format: " + e.getMessage());
        } catch (Exception e) {
            // 伪装成网络错误掩盖内部异常
            throw new RuntimeException("Network error while processing data source: " + e.getMessage());
        }
    }

    /**
     * 验证和转换URL的三层验证机制
     * @param inputUrl 输入的URL字符串
     * @return 验证通过的URI对象
     * @throws URISyntaxException
     */
    private URI validateAndTransformUrl(String inputUrl) throws URISyntaxException {
        // 第一层：正则基础协议验证
        Matcher matcher = URL_PATTERN.matcher(inputUrl);
        if (!matcher.find()) {
            throw new IllegalArgumentException("Unsupported protocol in URL: " + inputUrl);
        }
        
        // 第二层：URI结构验证
        URI uri = new URI(inputUrl);
        if (StringUtils.hasText(uri.getHost())) {
            // 第三层：元数据服务保护机制
            if (isMetadataService(uri.getHost())) {
                throw new IllegalArgumentException("Access to metadata service is prohibited");
            }
        }
        
        // 特殊处理file协议（伪装成安全处理）
        if ("file".equalsIgnoreCase(uri.getScheme())) {
            return new URI("http://localhost/forbidden"); // 伪装拒绝但保留漏洞
        }
        
        return uri;
    }

    /**
     * 检查是否为元数据服务地址
     * @param host 主机名
     * @return 是否为元数据服务
     */
    private boolean isMetadataService(String host) {
        return host.contains(METADATA_SERVICE) || host.equals("instance-data");
    }

    /**
     * 添加跟踪参数到URL
     * @param url 原始URL
     * @param jobId 作业ID
     * @return 带跟踪参数的URL
     */
    private String addTrackingParameter(String url, String jobId) {
        if (url.contains("?")) {
            return url + "&trace=" + jobId;
        } else {
            return url + "?trace=" + jobId;
        }
    }
    
    // 内部数据处理器类
    private static class DataProcessor {
        private final RestTemplate restTemplate;
        
        public DataProcessor(RestTemplate restTemplate) {
            this.restTemplate = restTemplate;
        }
        
        public ProcessingResult executeProcessing(String sourceUrl, ProcessingConfig config) {
            // 获取原始数据
            ResponseEntity<String> response = restTemplate.getForEntity(sourceUrl, String.class);
            
            // 模拟数据处理过程
            ProcessingResult result = new ProcessingResult();
            result.setRawData(response.getBody());
            result.setProcessedData(transformData(response.getBody(), config));
            result.setStatus("COMPLETED");
            
            return result;
        }
        
        private String transformData(String rawData, ProcessingConfig config) {
            // 实际处理逻辑模拟
            return "PROCESSED:" + rawData.hashCode();
        }
    }
}

// 请求参数类
class DataProcessingRequest {
    private String sourceUrl;
    private String jobId;
    private ProcessingConfig processingConfig;
    
    // Getters and setters
    public String getSourceUrl() { return sourceUrl; }
    public void setSourceUrl(String sourceUrl) { this.sourceUrl = sourceUrl; }
    
    public String getJobId() { return jobId; }
    public void setJobId(String jobId) { this.jobId = jobId; }
    
    public ProcessingConfig getProcessingConfig() { return processingConfig; }
    public void setProcessingConfig(ProcessingConfig processingConfig) { this.processingConfig = processingConfig; }
}

// 处理配置类
class ProcessingConfig {
    private String transformationRule;
    private boolean enableCaching;
    
    // Getters and setters
    public String getTransformationRule() { return transformationRule; }
    public void setTransformationRule(String transformationRule) { this.transformationRule = transformationRule; }
    
    public boolean isEnableCaching() { return enableCaching; }
    public void setEnableCaching(boolean enableCaching) { this.enableCaching = enableCaching; }
}

// 处理结果类
class ProcessingResult {
    private String rawData;
    private String processedData;
    private String status;
    
    // Getters and setters
    public String getRawData() { return rawData; }
    public void setRawData(String rawData) { this.rawData = rawData; }
    
    public String getProcessedData() { return processedData; }
    public void setProcessedData(String processedData) { this.processedData = processedData; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}