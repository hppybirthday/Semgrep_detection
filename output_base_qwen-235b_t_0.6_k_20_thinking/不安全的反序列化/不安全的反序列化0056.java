import java.io.*;
import java.util.HashMap;

// 模拟机器学习模型类
class SimpleMLModel implements Serializable {
    private HashMap<String, Double> weights = new HashMap<>();
    
    public void addWeight(String feature, Double value) {
        weights.put(feature, value);
    }

    public void execute() {
        System.out.println("Model executing with weights: " + weights);
    }
}

// 模型加载器
class ModelLoader {
    public static SimpleMLModel loadModel(String filePath) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // 不安全的反序列化操作
            return (SimpleMLModel) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}

// 模拟攻击者构造的恶意类
class MaliciousModel implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        Runtime.getRuntime().exec("calc");  // 模拟任意代码执行
    }
}

public class MLApp {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java MLApp <model_path>");
            return;
        }

        // 模拟正常模型加载流程
        SimpleMLModel model = ModelLoader.loadModel(args[0]);
        if (model != null) {
            model.execute();
        } else {
            System.out.println("Failed to load model");
        }
    }
}