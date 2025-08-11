import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;

@RestController
@RequestMapping("/models")
public class MathModelController {
    private final RedisTemplate<String, Object> redisTemplate;

    public MathModelController(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @PostMapping("/add")
    public String addModel(@RequestParam String obj) {
        // 漏洞点：直接反序列化用户输入的JSON字符串
        MathModel model = JSONObject.parseObject(obj, MathModel.class);
        String key = "model:" + model.getId();
        redisTemplate.boundValueOps(key).set(model);
        return "Model added";
    }

    @GetMapping("/get")
    public MathModel getModel(@RequestParam String id) {
        String key = "model:" + id;
        // 漏洞点：从Redis获取对象时未验证数据合法性
        return (MathModel) redisTemplate.boundValueOps(key).get();
    }

    static class MathModel implements Serializable {
        private String id;
        private String name;
        private double[] parameters;

        // Getters and setters
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public double[] getParameters() { return parameters; }
        public void setParameters(double[] parameters) { this.parameters = parameters; }
    }
}