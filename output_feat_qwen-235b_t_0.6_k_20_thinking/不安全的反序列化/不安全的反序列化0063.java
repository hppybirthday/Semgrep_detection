package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.Map;

@SpringBootApplication
public class VulnerableApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }

    @Bean
    public DynamicDataSourceService dynamicDataSourceService(RedisTemplate<String, Object> redisTemplate) {
        return new DynamicDataSourceService(redisTemplate);
    }
}

class DynamicDataSourceConfig implements Serializable {
    private String dataSourceName;
    private Map<String, Object> configProperties;

    // Getters and setters
    public String getDataSourceName() { return dataSourceName; }
    public void setDataSourceName(String dataSourceName) { this.dataSourceName = dataSourceName; }
    public Map<String, Object> getConfigProperties() { return configProperties; }
    public void setConfigProperties(Map<String, Object> configProperties) { this.configProperties = configProperties; }
}

@Service
class DynamicDataSourceService {
    private final RedisTemplate<String, Object> redisTemplate;

    public DynamicDataSourceService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public DynamicDataSourceConfig getCacheDynamicDataSourceModel(String cacheKey) {
        // Vulnerable: Untrusted data from Redis is deserialized without type checking
        return (DynamicDataSourceConfig) redisTemplate.opsForValue().get("ds_" + cacheKey);
    }

    public void saveDataSourceConfig(String cacheKey, DynamicDataSourceConfig config) {
        redisTemplate.opsForValue().set("ds_" + cacheKey, config);
    }
}

@RestController
@RequestMapping("/depot")
class DataSourceController {
    private final DynamicDataSourceService dataSourceService;

    public DataSourceController(DynamicDataSourceService dataSourceService) {
        this.dataSourceService = dataSourceService;
    }

    @PostMapping("/add")
    public String addDataSource(@RequestBody Map<String, Object> payload) {
        DynamicDataSourceConfig config = new DynamicDataSourceConfig();
        config.setDataSourceName((String) payload.get("name"));
        config.setConfigProperties((Map<String, Object>) payload.get("properties"));
        
        // Vulnerable: User input directly serialized to Redis
        dataSourceService.saveDataSourceConfig((String) payload.get("cacheKey"), config);
        return "Saved";
    }

    @PostMapping("/update")
    public String updateDataSource(@RequestParam String cacheKey) {
        // Trigger deserialization from Redis
        DynamicDataSourceConfig config = dataSourceService.getCacheDynamicDataSourceModel(cacheKey);
        return "Loaded config: " + config.getDataSourceName();
    }
}