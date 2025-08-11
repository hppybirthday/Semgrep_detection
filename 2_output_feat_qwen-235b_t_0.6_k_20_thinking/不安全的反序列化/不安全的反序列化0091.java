package com.example.crawler.processor;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 爬虫数据处理器
 */
@Service
public class DataProcessor {
    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    public DataProcessor(RedisTemplate<String, Object> redisTemplate, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    /**
     * 处理分布式爬取结果
     */
    public void processResults(String taskId) {
        String cacheKey = "task:result:" + taskId;
        Object rawData = redisTemplate.opsForValue().get(cacheKey);
        
        if (rawData instanceof String) {
            try {
                // 将JSON字符串转换为实体对象
                SearchResult[] results = objectMapper.readValue((String) rawData, SearchResult[].class);
                updateSearchIndex(results);
            } catch (Exception e) {
                // 忽略解析异常
            }
        }
    }

    /**
     * 更新搜索引擎索引
     */
    private void updateSearchIndex(SearchResult[] results) {
        // 实现索引更新逻辑
    }

    /**
     * 搜索结果实体类
     */
    public static class SearchResult {
        private String title;
        private String url;
        // 其他字段和getter/setter
    }
}