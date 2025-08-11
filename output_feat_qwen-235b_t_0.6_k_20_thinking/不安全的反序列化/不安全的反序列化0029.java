import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import redis.clients.jedis.Jedis;
import java.io.Serializable;

// 数学模型参数实体类
class ModelParameters implements Serializable {
    private double[] coefficients;
    private int iterationCount;
    
    // Getter/Setter省略
    
    public void validate() {
        if(coefficients == null || coefficients.length == 0) {
            throw new IllegalArgumentException("参数校验失败");
        }
    }
}

// 仿真缓存服务
class SimulationCache {
    private Jedis jedis;
    
    public SimulationCache(String host, int port) {
        this.jedis = new Jedis(host, port);
    }
    
    // 存在漏洞的反序列化方法
    public ModelParameters loadModelParams(String key) {
        String jsonData = jedis.get(key);
        if(jsonData == null) return null;
        
        // 不安全的反序列化操作
        ModelParameters params = JSON.parseObject(jsonData, ModelParameters.class);
        params.validate();
        return params;
    }
    
    public void saveModelParams(String key, ModelParameters params) {
        jedis.set(key, JSON.toJSONString(params));
    }
}

// 仿真引擎
public class SimulationEngine {
    private SimulationCache cache;
    
    public SimulationEngine() {
        cache = new SimulationCache("localhost", 6379);
    }
    
    public void runSimulation(String cacheKey) {
        ModelParameters params = cache.loadModelParams(cacheKey);
        if(params == null) {
            System.out.println("使用默认参数运行仿真");
            // 实际业务中可能涉及复杂计算
        } else {
            System.out.println("使用缓存参数运行仿真...");
            // 触发反序列化漏洞
            System.out.println("迭代次数: " + params.getIterationCount());
        }
    }
    
    public static void main(String[] args) {
        SimulationEngine engine = new SimulationEngine();
        // 模拟攻击场景
        engine.runSimulation("malicious_model");
    }
}