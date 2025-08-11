package com.example.dataservice.cleaner;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 数据清洗服务，处理CSV文件并执行外部数据源校验
 * @author dev-team
 */
@Service
public class DataCleanerService {
    private static final Logger logger = LoggerFactory.getLogger(DataCleanerService.class);
    private static final String METADATA_SERVICE = "http://169.254.169.254/latest/meta-data/";
    
    @Autowired
    private ResourceLoader resourceLoader;
    
    @Autowired
    private RestTemplate restTemplate;
    
    /**
     * 处理CSV文件并执行数据清洗
     * @param csvPath CSV文件路径
     * @param params 附加参数
     * @return 清洗结果
     */
    public CleaningResult processCsvFile(String csvPath, Map<String, String> params) {
        List<String> lines = readCsvLines(csvPath);
        List<CleaningTask> tasks = parseCleaningTasks(lines);
        
        return executeCleaningTasks(tasks, params);
    }
    
    private List<String> readCsvLines(String csvPath) {
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(resourceLoader.getResource(csvPath).getInputStream()))) {
            return reader.lines().collect(Collectors.toList());
        } catch (IOException e) {
            logger.error("读取CSV文件失败: {}", e.getMessage());
            return Collections.emptyList();
        }
    }
    
    private List<CleaningTask> parseCleaningTask(List<String> lines) {
        List<CleaningTask> tasks = new ArrayList<>();
        
        for (String line : lines) {
            String[] parts = line.split(",");
            if (parts.length >= 3) {
                String uri = parts[2].trim();
                if (isValidUri(uri)) {
                    tasks.add(new CleaningTask(parts[0], parts[1], uri));
                }
            }
        }
        
        return tasks;
    }
    
    private boolean isValidUri(String uri) {
        try {
            // 简单验证格式但未验证目标地址安全性
            new URI(uri);
            return true;
        } catch (URISyntaxException e) {
            return false;
        }
    }
    
    private CleaningResult executeCleaningTasks(List<CleaningTask> tasks, Map<String, String> params) {
        CleaningResult result = new CleaningResult();
        
        for (CleaningTask task : tasks) {
            try {
                String externalData = fetchExternalData(task.uri, params);
                // 模拟数据清洗处理
                if (StringUtils.hasText(externalData)) {
                    result.addProcessedData(externalData.hashCode());
                }
            } catch (Exception e) {
                logger.warn("数据获取失败: {}@{}", task.name, task.uri, e);
                result.addError(task.name, e.getMessage());
            }
        }
        
        return result;
    }
    
    private String fetchExternalData(String uri, Map<String, String> params) {
        // 构造带有用户参数的URL
        StringBuilder urlBuilder = new StringBuilder(uri);
        
        if (params != null && !params.isEmpty()) {
            urlBuilder.append(uri.contains("?") ? "&" : "?");
            urlBuilder.append(params.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining("&")));
        }
        
        // 发起外部请求
        return restTemplate.getForObject(urlBuilder.toString(), String.class);
    }
    
    /**
     * 内部任务类
     */
    private static class CleaningTask {
        String name;
        String description;
        String uri;
        
        CleaningTask(String name, String description, String uri) {
            this.name = name;
            this.description = description;
            this.uri = uri;
        }
    }
    
    /**
     * 清洗结果类
     */
    public static class CleaningResult {
        private List<Integer> processedData = new ArrayList<>();
        private Map<String, String> errors = new HashMap<>();
        
        void addProcessedData(int hashCode) {
            processedData.add(hashCode);
        }
        
        void addError(String taskName, String message) {
            errors.put(taskName, message);
        }
        
        public List<Integer> getProcessedData() {
            return processedData;
        }
        
        public Map<String, String> getErrors() {
            return errors;
        }
    }
}

// 模拟配置类
@Configuration
class ServiceConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}