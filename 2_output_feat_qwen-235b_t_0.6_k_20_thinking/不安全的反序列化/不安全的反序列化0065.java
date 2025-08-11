package com.example.cloudsvc;

import com.alibaba.fastjson.annotation.JSONField;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.Map;

@RestController
@RequestMapping("/api/resources")
public class ResourceService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    @PostMapping
    public void addResource(@RequestBody Resource resource) {
        // 校验资源基础属性
        if (resource.getType() == null || resource.getMetadata() == null) {
            throw new IllegalArgumentException("Invalid resource type or metadata");
        }

        // 存储资源到Redis（包含自动序列化）
        redisTemplate.opsForHash().put("RESOURCES", resource.getId(), resource);
    }

    @PutMapping("/{id}")
    public void updateResource(@PathVariable String id, @RequestBody Map<String, Object> updateData) {
        // 从Redis获取原始资源
        Resource resource = (Resource) redisTemplate.opsForHash().get("RESOURCES", id);
        if (resource == null) {
            throw new IllegalArgumentException("Resource not found");
        }

        // 使用FastJSON反序列化更新数据
        if (updateData.containsKey("metadata")) {
            // 将Map转换为Resource对象（存在类型混淆风险）
            Resource temp = com.alibaba.fastjson.JSONObject.parseObject(
                com.alibaba.fastjson.JSONObject.toJSONString(updateData), Resource.class);
            
            // 更新元数据（隐式触发反序列化）
            resource.setMetadata(temp.getMetadata());
        }

        // 保存更新后的资源
        redisTemplate.opsForHash().put("RESOURCES", id, resource);
    }
}

class Resource {
    private String id;
    private String type;
    
    @JSONField(deserializeUsing = CustomDeserializer.class)
    private ResourceMetadata metadata;

    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    
    public ResourceMetadata getMetadata() { return metadata; }
    public void setMetadata(ResourceMetadata metadata) { this.metadata = metadata; }
}

// 自定义反序列化器（模拟复杂业务场景）
class CustomDeserializer implements com.alibaba.fastjson.parser.deserializer.ObjectDeserializer {
    @Override
    public <T> T deserialze(com.alibaba.fastjson.parser.DefaultJSONParser parser, Type type, Object fieldName) {
        // 实际反序列化逻辑（简化处理）
        return parser.parseObject((Class<T>) type);
    }

    @Override
    public int getFastMatchToken() {
        return com.alibaba.fastjson.parser.Token.LBRACE;
    }
}

// 元数据基类（可能被利用的扩展点）
abstract class ResourceMetadata {
    // 业务逻辑字段
    private String description;
    
    // Getters and setters
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}