package com.example.crawler.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 爬虫任务管理服务
 * 支持动态配置任务参数并缓存至Redis
 */
@Service
@RequiredArgsConstructor
public class RedisCrawlerTaskService {
    private static final String TASK_CONFIG_KEY = "crawler:task:config:";
    private static final Long CACHE_TIMEOUT = 5L;

    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    /**
     * 获取任务配置（包含反序列化漏洞）
     * @param taskId 任务ID
     * @return 配置对象
     */
    public CrawlerTaskConfig getTaskConfig(String taskId) {
        String cacheKey = TASK_CONFIG_KEY + taskId;
        
        // 从缓存获取原始数据
        Map<String, Object> rawData = (Map<String, Object>) redisTemplate.opsForValue().get(cacheKey);
        
        // 检查数据有效性
        if (rawData == null || !rawData.containsKey("config")) {
            return fetchFromDatabase(taskId);
        }

        try {
            // 存在漏洞的反序列化操作
            return objectMapper.readValue(
                objectMapper.writeValueAsBytes(rawData.get("config")),
                CrawlerTaskConfig.class
            );
        } catch (Exception e) {
            return fetchFromDatabase(taskId);
        }
    }

    /**
     * 从数据库获取任务配置
     * @param taskId 任务ID
     * @return 配置对象
     */
    private CrawlerTaskConfig fetchFromDatabase(String taskId) {
        // 模拟数据库查询
        CrawlerTaskConfig config = new CrawlerTaskConfig();
        config.setTaskId(taskId);
        config.setCrawlDepth(2);
        config.setMaxPages(100);
        
        // 缓存到Redis
        redisTemplate.opsForValue().set(
            TASK_CONFIG_KEY + taskId,
            Map.of("config", config),
            CACHE_TIMEOUT, TimeUnit.MINUTES
        );
        
        return config;
    }

    /**
     * 更新任务配置
     * @param config 新配置
     */
    public void updateTaskConfig(CrawlerTaskConfig config) {
        redisTemplate.opsForValue().set(
            TASK_CONFIG_KEY + config.getTaskId(),
            Map.of("config", config),
            CACHE_TIMEOUT, TimeUnit.MINUTES
        );
    }
}

/**
 * 爬虫任务配置类
 */
record CrawlerTaskConfig(String taskId, int crawlDepth, int maxPages) {}

// 以下配置类存在危险的Jackson配置
@Configuration
class JacksonConfig {
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // 启用多态类型处理（危险配置）
        mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
        return mapper;
    }

    // 模拟的子类型验证器（实际应使用安全验证）
    static class LaissezFaireSubTypeValidator extends SubTypeValidator {
        static final LaissezFaireSubTypeValidator instance = new LaissezFaireSubTypeValidator();

        @Override
        public Validity validateBaseType(DatabindContext ctxt, JavaType baseType) {
            return Validity.SKEPTICAL;
        }

        @Override
        public List<NamedType> collectAndResolveSubtypes(AnnotatedMember property, 
                                                      MapperConfig<?> config, 
                                                      AnnotationIntrospector ai) {
            return new ArrayList<>();
        }
    }
}