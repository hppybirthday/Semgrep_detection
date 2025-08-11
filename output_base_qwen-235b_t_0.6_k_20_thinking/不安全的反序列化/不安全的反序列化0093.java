import java.io.*;
import java.util.ArrayList;
import java.util.List;

// 数学模型基类
class MathModel implements Serializable {
    private String modelName;
    private List<Double> parameters = new ArrayList<>();
    
    public MathModel(String name) {
        this.modelName = name;
    }
    
    public void addParameter(double param) {
        parameters.add(param);
    }
    
    public void displayModel() {
        System.out.println("Model: " + modelName);
        System.out.println("Parameters: " + parameters);
    }
}

// 模型持久化类
class ModelPersistence {
    // 漏洞点：直接反序列化不可信数据
    public static MathModel loadModel(String filename) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            // 危险操作：直接强制转换反序列化对象
            return (MathModel) ois.readObject();
        }
    }
    
    public static void saveModel(MathModel model, String filename) throws Exception {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(model);
        }
    }
}

// 模型仿真引擎
class SimulationEngine {
    public void runSimulation(MathModel model) {
        System.out.println("Running simulation...");
        model.displayModel();
        // 模拟计算过程
        double result = 0;
        for (Double param : model.parameters) {
            result += param * Math.random();
        }
        System.out.println("Simulation result: " + result);
    }
}

// 漏洞演示类
public class VulnerableSimulation {
    public static void main(String[] args) throws Exception {
        // 正常使用场景
        MathModel model = new MathModel("LinearRegression");
        model.addParameter(1.5);
        model.addParameter(2.8);
        
        // 保存模型到文件
        ModelPersistence.saveModel(model, "model.ser");
        
        // 加载并运行仿真（存在漏洞）
        SimulationEngine engine = new SimulationEngine();
        MathModel loadedModel = ModelPersistence.loadModel("model.ser");
        engine.runSimulation(loadedModel);
        
        // 攻击演示说明：
        // 攻击者可通过构造恶意序列化文件替换model.ser
        // 在反序列化时触发任意代码执行
        // 例如：通过Java反序列化gadget执行系统命令
    }
}