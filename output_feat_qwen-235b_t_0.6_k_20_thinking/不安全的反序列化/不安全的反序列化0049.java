package com.example.crawler;

import org.springframework.web.bind.annotation.*;
import redis.clients.jedis.Jedis;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/crawler")
public class CrawlerController {
    private final CrawlerTaskService crawlerTaskService;

    public CrawlerController() {
        this.crawlerTaskService = new CrawlerTaskService();
    }

    @PostMapping("/update")
    public String updateSettings(@RequestBody ConfigDTO dto) {
        try {
            crawlerTaskService.updateDynamicConfig(dto.getConfigData());
            return "Config updated successfully";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class ConfigDTO {
    private byte[] configData;

    public byte[] getConfigData() { return configData; }
    public void setConfigData(byte[] configData) { this.configData = configData; }
}

class CrawlerTaskService {
    private final RedisConfigLoader configLoader;

    public CrawlerTaskService() {
        this.configLoader = new RedisConfigLoader();
    }

    public void dynamicUpdate(byte[] rawData) {
        try {
            Object config = configLoader.loadFromRedis(rawData);
            if (config instanceof CrawlerConfig) {
                ((CrawlerConfig) config).applyConfiguration();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class RedisConfigLoader {
    public Object loadFromRedis(byte[] data) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }
}

interface CrawlerConfig {
    void applyConfiguration();
}

class WebCrawlerConfig implements CrawlerConfig, Serializable {
    private Map<String, String> settings = new HashMap<>();

    public void setSettings(Map<String, String> settings) {
        this.settings = settings;
    }

    @Override
    public void applyConfiguration() {
        System.out.println("Applying crawler settings: " + settings);
    }
}

// 恶意类示例（攻击者构造）
class MaliciousPayload implements Serializable {
    private static final long serialVersionUID = 1L;
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}