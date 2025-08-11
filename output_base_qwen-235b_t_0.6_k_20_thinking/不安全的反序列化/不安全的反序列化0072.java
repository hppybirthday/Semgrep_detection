import java.io.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

class ModelData implements Serializable {
    private static final long serialVersionUID = 1L;
    private Map<String, Double> features = new HashMap<>();
    
    public ModelData addFeature(String key, Double value) {
        features.put(key, value);
        return this;
    }
    
    public Map<String, Double> getFeatures() {
        return features;
    }
}

public class MLProcessor {
    public static void main(String[] args) {
        String modelPath = System.getProperty("user.home") + "/.ml_model.ser";
        
        // 模拟训练数据保存
        saveModel(modelPath, new ModelData()
            .addFeature("age", 25.0)
            .addFeature("score", 0.85));
            
        // 模拟模型加载处理
        Function<String, Optional<ModelData>> loadModel = path -> {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path))) {
                return Optional.of((ModelData) ois.readObject());
            } catch (Exception e) {
                System.err.println("Load error: " + e);
                return Optional.empty();
            }
        };
        
        // 漏洞触发点：反序列化不可信数据
        loadModel.apply(modelPath).ifPresent(model -> {
            model.getFeatures().forEach((k, v) -> 
                System.out.println(k + ": " + v));
        });
        
        // 模拟攻击面：处理用户提供的恶意模型
        if (args.length > 0) {
            loadModel.apply(args[0]).ifPresent(model -> {
                System.out.println("Attack test: " + model.getFeatures());
            });
        }
    }
    
    private static void saveModel(String path, ModelData data) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(path))) {
            oos.writeObject(data);
        } catch (Exception e) {
            System.err.println("Save error: " + e);
        }
    }
}