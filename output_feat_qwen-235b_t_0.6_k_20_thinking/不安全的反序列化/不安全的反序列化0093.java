import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;
import com.alibaba.fastjson.JSON;
import java.io.Serializable;
import java.util.HashMap;

@RestController
@RequestMapping("/simulation")
public class SimulationController {
    private final RedisTemplate<String, Object> redisTemplate;

    public SimulationController(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @PostMapping("/model")
    public String createModel(@RequestBody String modelData) {
        // 使用FastJSON反序列化基础模型配置
        HashMap<String, Object> config = JSON.parseObject(modelData, HashMap.class);
        
        // 从Redis获取历史模型数据（存在不安全反序列化）
        String modelKey = "model:" + config.get("id");
        FluidSimulationModel model = (FluidSimulationModel) redisTemplate.opsForValue().get(modelKey);
        
        if (model == null) {
            // 创建新模型并存储到Redis
            model = new FluidSimulationModel();
            model.setId((String) config.get("id"));
            model.setParameters((HashMap<String, Double>) config.get("parameters"));
            redisTemplate.opsForValue().set(modelKey, model); // 使用JdkSerializationRedisSerializer
        }
        
        // 执行模拟计算
        return model.runSimulation();
    }
}

// 数学建模领域对象
class FluidSimulationModel implements Serializable {
    private String id;
    private HashMap<String, Double> parameters;
    private transient double[][] velocityField; // 不参与序列化

    public String runSimulation() {
        // 实际模拟逻辑（此处简化）
        return "Simulation " + id + " completed with velocity: " + (velocityField != null ? velocityField.length : "null");
    }

    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public HashMap<String, Double> getParameters() { return parameters; }
    public void setParameters(HashMap<String, Double> parameters) { this.parameters = parameters; }
}

// Redis配置示例（不安全的默认序列化）
/*
@Bean
public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
    RedisTemplate<String, Object> template = new RedisTemplate<>();
    template.setConnectionFactory(factory);
    template.setKeySerializer(new StringRedisSerializer());
    template.setValueSerializer(new JdkSerializationRedisSerializer()); // 不安全的序列化方式
    return template;
}
*/