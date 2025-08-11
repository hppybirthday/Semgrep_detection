package com.example.vulnerableapp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.List;

@RestController
@RequestMapping("/api")
public class VulnerableController {
    @Autowired
    private CrawlingService crawlingService;

    @PostMapping("/batchSetStatus")
    public String batchSetStatus(@RequestParam String data) {
        crawlingService.setColumnComment(data);
        return "Status updated";
    }
}

@Service
class CrawlingService {
    private String columnComment;
    private final RedisTemplate<String, Object> redisTemplate;

    @Autowired
    public CrawlingService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void setColumnComment(String jsonComment) {
        // Vulnerable line: Untrusted deserialization with Fastjson
        JSONObject commentObj = JSON.parseObject(jsonComment);
        this.columnComment = commentObj.getString("comment");
        
        // Simulated business logic that could be exploited
        if (commentObj.containsKey("spiderConfig")) {
            SpiderConfig config = JSON.parseObject(
                commentObj.getString("spiderConfig"), 
                SpiderConfig.class
            );
            redisTemplate.opsForValue().set("spider:config", config);
        }
    }
}

class SpiderConfig implements Serializable {
    private List<String> urls;
    private int depth;
    private String proxy;
    // Getters and setters
    
    public List<String> getUrls() { return urls; }
    public void setUrls(List<String> urls) { this.urls = urls; }
    public int getDepth() { return depth; }
    public void setDepth(int depth) { this.depth = depth; }
    public String getProxy() { return proxy; }
    public void setProxy(String proxy) { this.proxy = proxy; }
}

// Spring configuration (simplified)
@Configuration
class AppConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate() {
        return new RedisTemplate<>();
    }
}