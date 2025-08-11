package com.example.crawler.config;

import com.alibaba.fastjson.JSON;
import com.example.crawler.model.Config;
import com.example.crawler.parser.ConfigParser;
import com.example.crawler.storage.RedisConfigStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 系统配置服务，处理配置更新与验证
 */
@Service
public class ConfigService {
    @Autowired
    private RedisConfigStore redisConfigStore;
    
    @Autowired
    private ConfigParser configParser;

    /**
     * 更新系统配置并验证有效性
     * @param config 新配置数据
     * @throws Exception 配置异常
     */
    public void updateSystemConfig(Config config) throws Exception {
        if (config == null || !validateConfig(config)) {
            throw new IllegalArgumentException("配置校验失败");
        }
        
        // 解析扩展字段配置
        if (config.getAuthProvider() != null) {
            configParser.parseAuthProvider(config.getAuthProvider());
        }
        
        // 存储到Redis供其他服务使用
        redisConfigStore.saveConfig(config);
    }

    /**
     * 验证配置基础字段合法性
     */
    private boolean validateConfig(Config config) {
        if (config.getColumnComment() == null || config.getColumnComment().length() < 5) {
            return false;
        }
        
        try {
            // 解析列注释扩展属性（业务需求）
            configParser.parseColumnAttributes(config.getColumnComment());
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

// ---

package com.example.crawler.parser;

import com.alibaba.fastjson.JSON;
import com.example.crawler.model.ColumnConfigInfo;
import org.springframework.stereotype.Component;

/**
 * 配置解析器，处理不同来源的配置数据
 */
@Component
public class ConfigParser {
    /**
     * 解析列属性配置
     * @param columnComment 列注释文本
     * @throws Exception 解析异常
     */
    public void parseColumnAttributes(String columnComment) throws Exception {
        if (columnComment.startsWith("{")) {
            // 反序列化JSON格式的列配置（存在漏洞点）
            ColumnConfigInfo config = JSON.parseObject(columnComment, ColumnConfigInfo.class);
            // 使用解析后的配置初始化爬虫参数
            System.setProperty("crawler.proxy", config.getProxyServer());
        }
    }

    /**
     * 解析认证提供方配置
     */
    public void parseAuthProvider(String authProvider) {
        // 业务逻辑处理...
    }
}

// ---

package com.example.crawler.storage;

import com.alibaba.fastjson.JSON;
import com.example.crawler.model.Config;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

/**
 * Redis配置存储服务，实现配置持久化
 */
@Service
public class RedisConfigStore {
    private final RedisTemplate<String, Object> redisTemplate;

    public RedisConfigStore(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
        // 设置自定义序列化方式
        redisTemplate.setValueSerializer(new RedisSerializer<Object>() {
            @Override
            public byte[] serialize(Object o) {
                return JSON.toJSONString(o).getBytes();
            }

            @Override
            public Object deserialize(byte[] bytes) {
                if (bytes == null) return null;
                // 从Redis反序列化时触发漏洞（关键点）
                return JSON.parseObject(new String(bytes), Config.class);
            }
        });
    }

    /**
     * 从Redis获取配置
     */
    public Config getConfigFromRedis(String key) {
        return (Config) redisTemplate.opsForValue().get("CONFIG:" + key);
    }

    /**
     * 存储配置到Redis
     */
    public void saveConfig(Config config) {
        redisTemplate.opsForValue().set("CONFIG:" + config.getId(), config);
    }
}

// ---

package com.example.crawler.model;

import lombok.Data;

/**
 * 系统配置模型
 */
@Data
public class Config {
    private String id;
    private String columnComment;
    private String authProvider;
    // 其他配置字段...
}

// ---

package com.example.crawler.model;

import lombok.Data;

/**
 * 列配置信息类
 */
@Data
public class ColumnConfigInfo {
    private String proxyServer;
    // 其他扩展属性...
}