import java.io.*;
import java.util.function.Function;
import java.util.Base64;

// 机器学习模型类（可序列化）
@FunctionalInterface
interface ModelLoader {
    Object loadModel(InputStream is) throws Exception;
}

// 模型预测服务
@FunctionalInterface
interface PredictionService {
    double predict(Object model, double[] input);
}

public class MLModelService {
    
    // 不安全的反序列化实现
    public static final ModelLoader UNSAFE_LOADER = is -> {
        try (ObjectInputStream ois = new ObjectInputStream(is)) {
            return ois.readObject(); // 漏洞触发点
        }
    };

    // 预测执行方法
    public static final PredictionService EXECUTOR = (model, input) -> {
        if (model instanceof MLModel) {
            return ((MLModel) model).predict(input);
        }
        return -1.0;
    };

    // 模拟反序列化攻击
    public static void simulateAttack(String base64Data) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            ois.readObject(); // 攻击执行点
            ois.close();
        } catch (Exception e) {
            System.out.println("Attack failed: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        // 正常模型加载流程
        try {
            // 模拟从不可信来源读取数据
            String maliciousData = "rO0ABXNyABdqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnH1uQDAAFMAARlbGVtZHN0AAtbTGphdmEvbGFuZy9PYmplY3Q7eHAAAAA=";
            
            // 使用不安全加载器加载模型
            Object model = UNSAFE_LOADER.loadModel(new ByteArrayInputStream(
                Base64.getDecoder().decode(maliciousData)));

            // 执行预测（可能触发恶意代码）
            double result = EXECUTOR.predict(model, new double[]{1.0, 2.0});
            System.out.println("Prediction result: " + result);
            
        } catch (Exception e) {
            System.out.println("Normal execution failed: " + e.getMessage());
        }
    }
}

// 可序列化的模型类
class MLModel implements Serializable {
    private static final long serialVersionUID = 1L;
    
    public double predict(double[] input) {
        System.out.println("Executing normal prediction...");
        return input[0] + input[1];
    }
}