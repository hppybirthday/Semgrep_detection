import java.io.*;
import java.util.*;

// 领域层：数学模型定义
class MathModel implements Serializable {
    private String modelName;
    private double[] coefficients;
    private transient Map<String, Object> metadata = new HashMap<>();

    public MathModel(String name, double[] coeffs) {
        this.modelName = name;
        this.coefficients = coeffs;
    }

    // 模拟模型执行
    public void execute() {
        System.out.println("Executing model: " + modelName);
        double result = 0;
        for (double d : coefficients) {
            result += d;
        }
        System.out.println("Sum result: " + result);
    }
}

// 基础设施层：模型持久化
class FileModelRepository {
    public MathModel loadModel(String filePath) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // 不安全的反序列化操作
            Object obj = ois.readObject();
            if (obj instanceof MathModel) {
                return (MathModel) obj;
            }
            throw new IllegalArgumentException("Invalid model file");
        }
    }

    public void saveModel(MathModel model, String filePath) throws Exception {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(model);
        }
    }
}

// 应用层：模型服务
class ModelService {
    private FileModelRepository repository = new FileModelRepository();

    public void runModel(String filePath) throws Exception {
        MathModel model = repository.loadModel(filePath);
        model.execute();
    }
}

// 恶意类示例（攻击者构造）
class MaliciousPayload implements Serializable {
    private String cmd;
    public MaliciousPayload(String cmd) { this.cmd = cmd; }
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟恶意行为
        Runtime.getRuntime().exec(cmd);
    }
}

// 主程序入口
public class SimulationApp {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java SimulationApp [save|run] [filename]");
            return;
        }

        try {
            ModelService service = new ModelService();
            if (args[0].equals("save")) {
                MathModel model = new MathModel("TestModel", new double[]{1.0, 2.0, 3.0});
                service.getRepository().saveModel(model, args[1]);
                System.out.println("Model saved");
            } else if (args[0].equals("run")) {
                service.runModel(args[1]);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}