import java.io.*;
import java.lang.reflect.Method;
import java.util.HashMap;

// 数学模型基类
abstract class MathModel implements Serializable {
    protected String modelName;
    protected HashMap<String, Double> parameters = new HashMap<>();
    
    public abstract double calculate();
    
    public String getModelName() { return modelName; }
}

// 动态模型实现类
class DynamicModel extends MathModel {
    private String formula;
    
    public DynamicModel(String name, String formula) {
        this.modelName = name;
        this.formula = formula;
    }
    
    // 使用反射执行公式计算
    public double calculate() {
        try {
            // 模拟元编程的动态代码执行
            Method method = Math.class.getMethod("eval", String.class);
            return (double) method.invoke(null, formula);
        } catch (Exception e) {
            return 0;
        }
    }
}

// 模型处理器
class ModelProcessor {
    // 不安全的反序列化操作
    public static MathModel loadModel(String filename) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(
             new FileInputStream(filename))) {
            // 危险的反序列化操作
            Object obj = ois.readObject();
            if (obj instanceof MathModel) {
                return (MathModel) obj;
            }
            return null;
        }
    }
    
    public static void processModel(MathModel model) {
        System.out.println("模型名称: " + model.getModelName());
        System.out.println("计算结果: " + model.calculate());
    }
}

// 恶意类示例（攻击者构造的Payload）
class MaliciousModel extends MathModel {
    public MaliciousModel() {
        this.modelName = "EvilModel";
    }
    
    private void readObject(ObjectInputStream in) throws Exception {
        // 恶意代码执行
        Runtime.getRuntime().exec("calc");
    }
    
    public double calculate() { return 0; }
}

// 测试类
public class Simulation {
    public static void main(String[] args) {
        try {
            // 正常模型序列化
            DynamicModel model = new DynamicModel("TestModel", "Math.sqrt(9)");
            try (ObjectOutputStream oos = new ObjectOutputStream(
                 new FileOutputStream("model.ser"))) {
                oos.writeObject(model);
            }
            
            // 漏洞触发点：反序列化不可信数据
            MathModel loadedModel = ModelProcessor.loadModel("model.ser");
            ModelProcessor.processModel(loadedModel);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}