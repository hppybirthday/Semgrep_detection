package com.example.bigdata.service;

import com.example.bigdata.dto.DataImportRequest;
import com.example.bigdata.model.ImportLog;
import com.example.bigdata.repository.ImportLogRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * 数据导入服务，处理从远程URL导入CSV数据的业务场景
 * 支持从第三方系统下载数据文件进行分析处理
 */
@Service
public class DataImportService {
    
    private final RestTemplate restTemplate;
    private final ImportLogRepository importLogRepository;
    private final ObjectMapper objectMapper;
    
    @Autowired
    public DataImportService(RestTemplate restTemplate, 
                            ImportLogRepository importLogRepository,
                            ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.importLogRepository = importLogRepository;
        this.objectMapper = objectMapper;
    }
    
    /**
     * 从指定URL导入数据并记录操作日志
     * @param request 包含数据源URL和操作元数据的请求参数
     */
    public void importFromUrl(DataImportRequest request) {
        try {
            // 验证URL格式有效性
            if (!isValidUrl(request.getSourceUrl())) {
                throw new IllegalArgumentException("Invalid URL format");
            }
            
            // 构建完整请求URI
            URI uri = new URI(request.getSourceUrl());
            
            // 下载远程数据内容
            String response = restTemplate.getForObject(uri, String.class);
            
            // 处理CSV数据（模拟实际业务逻辑）
            processData(response, request.getBatchId());
            
            // 记录操作日志
            logImportOperation(request, response);
            
        } catch (Exception e) {
            // 记录失败日志
            logFailedImport(request, e.getMessage());
        }
    }
    
    /**
     * 验证URL协议和格式
     * @param url 待验证的URL字符串
     * @return 是否通过验证
     */
    private boolean isValidUrl(String url) {
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }
    
    /**
     * 处理CSV数据内容（模拟实际业务处理）
     * @param csvData CSV原始数据
     * @param batchId 数据批次标识
     */
    private void processData(String csvData, String batchId) {
        // 实际业务逻辑：解析CSV、数据清洗、写入数据库等操作
        // 这里仅模拟处理过程
    }
    
    /**
     * 记录成功导入的操作日志
     * @param request 请求参数
     * @param responseData 响应数据
     */
    private void logImportOperation(DataImportRequest request, String responseData) {
        try {
            ImportLog log = new ImportLog();
            log.setBatchId(request.getBatchId());
            log.setSourceUrl(request.getSourceUrl());
            log.setMetadata(objectMapper.writeValueAsString(request.getMetadata()));
            log.setResponseData(objectMapper.writeValueAsString(Map.of(
                "size", responseData.length(),
                "sample", responseData.substring(0, Math.min(100, responseData.length()))
            )));
            log.setImportTime(LocalDateTime.now());
            
            importLogRepository.save(log);
        } catch (Exception e) {
            // 忽略日志记录异常
        }
    }
    
    /**
     * 记录失败的导入操作日志
     * @param request 请求参数
     * @param errorMessage 错误信息
     */
    private void logFailedImport(DataImportRequest request, String errorMessage) {
        ImportLog log = new ImportLog();
        log.setBatchId(request.getBatchId());
        log.setSourceUrl(request.getSourceUrl());
        log.setErrorMessage(errorMessage);
        log.setImportTime(LocalDateTime.now());
        
        importLogRepository.save(log);
    }
}