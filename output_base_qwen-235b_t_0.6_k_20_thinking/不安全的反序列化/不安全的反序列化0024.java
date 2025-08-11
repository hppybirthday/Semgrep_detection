import java.io.*;
import java.util.*;

// 机器学习模型基类
class MLModel implements Serializable {
    private static final long serialVersionUID = 1L;
    protected String modelName;
    protected transient Map<String, Object> metadata = new HashMap<>();

    public MLModel(String modelName) {
        this.modelName = modelName;
        metadata.put("created_at", new Date());
    }

    public String predict(String input) {
        // 实际预测逻辑
        return "Prediction for: " + input;
    }
}

// 模型加载器（存在漏洞）
class ModelLoader {
    public static MLModel loadModel(String filePath) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // 漏洞点：直接反序列化不可信数据
            Object obj = ois.readObject();
            if (obj instanceof MLModel) {
                return (MLModel) obj;
            }
            throw new InvalidObjectException("Invalid model type");
        } catch (Exception e) {
            System.err.println("[SECURITY] Model loading failed: " + e.getMessage());
            return null;
        }
    }
}

// 攻击者构造的恶意类
class MaliciousModel extends MLModel {
    public MaliciousModel() {
        super("EvilModel");
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 恶意代码执行
        Runtime.getRuntime().exec("calc"); // 模拟命令执行
    }
}

// 主程序
public class MLApp {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java MLApp <model_path>");
            return;
        }

        // 模型加载
        MLModel model = ModelLoader.loadModel(args[0]);
        if (model != null) {
            System.out.println("Model loaded: " + model.modelName);
            System.out.println(model.predict("test_data"));
        }
    }
}