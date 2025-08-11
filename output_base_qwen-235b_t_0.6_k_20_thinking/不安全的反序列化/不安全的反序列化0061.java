import java.io.*;
import java.util.*;

// 数学建模参数类
class ModelParameters implements Serializable {
    private static final long serialVersionUID = 1L;
    private Map<String, Double> variables = new HashMap<>();
    private List<String> equations = new ArrayList<>();
    
    public void addVariable(String name, Double value) {
        variables.put(name, value);
    }
    
    public void addEquation(String equation) {
        equations.add(equation);
    }
    
    @Override
    public String toString() {
        return "Variables: " + variables + "\
Equations: " + equations;
    }
}

// 仿真管理器类
class SimulationManager {
    // 声明式配置：模型存储路径
    private static final String MODEL_PATH = "./model.ser";
    
    // 声明式工作流：执行建模流程
    public void runSimulation() {
        try {
            // 创建模型参数
            ModelParameters params = createModel();
            
            // 序列化保存模型
            saveParameters(params);
            
            // 模拟攻击者篡改文件后的反序列化
            ModelParameters loadedParams = loadParameters();
            System.out.println("Loaded Model: " + loadedParams);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // 创建数学模型
    private ModelParameters createModel() {
        ModelParameters params = new ModelParameters();
        params.addVariable("x", 1.0);
        params.addVariable("y", 2.0);
        params.addEquation("dx/dt = -k*x");
        return params;
    }
    
    // 不安全的序列化方法
    private void saveParameters(ModelParameters params) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(
             new FileOutputStream(MODEL_PATH))) {
            oos.writeObject(params);
        }
    }
    
    // 不安全的反序列化方法（漏洞点）
    private ModelParameters loadParameters() throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(
             new FileInputStream(MODEL_PATH))) {
            // 危险的反序列化操作
            return (ModelParameters) ois.readObject();
        }
    }
}

// 恶意类示例（攻击者构造）
class MaliciousClass implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private void execCommand(String cmd) throws IOException {
        Runtime.getRuntime().exec(cmd);
    }
    
    private void readObject(ObjectInputStream in) 
        throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 恶意代码执行
        execCommand("calc"); // 示例：弹出计算器
    }
}

// 主程序
public class UnsafeDeserialization {
    public static void main(String[] args) {
        SimulationManager manager = new SimulationManager();
        manager.runSimulation();
    }
}