import java.io.*;
import java.util.ArrayList;
import java.util.List;

// 数学建模核心类
class SimulationModel implements Serializable {
    private String modelName;
    private List<Double> parameters = new ArrayList<>();

    public SimulationModel(String name) {
        this.modelName = name;
    }

    public void addParameter(double param) {
        parameters.add(param);
    }

    public void runSimulation() {
        System.out.println("Running simulation: " + modelName);
        System.out.println("Parameters: " + parameters);
    }
}

// 模型管理器类
class SimulationManager {
    // 漏洞点：不安全的反序列化
    public SimulationModel loadModel(String filePath) {
        try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(filePath))) {
            // 直接反序列化用户输入路径的文件
            return (SimulationModel) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void saveModel(SimulationModel model, String filePath) {
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(filePath))) {
            oos.writeObject(model);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 主程序
public class MathModelSimulator {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java MathModelSimulator [save|load] [filename]");
            return;
        }

        SimulationManager manager = new SimulationManager();
        
        if (args[0].equals("save")) {
            SimulationModel model = new SimulationModel("TestModel");
            model.addParameter(3.14);
            model.addParameter(2.718);
            manager.saveModel(model, args[1]);
            System.out.println("Model saved successfully");
        } 
        else if (args[0].equals("load")) {
            // 漏洞触发点：加载用户指定的序列化文件
            SimulationModel loadedModel = manager.loadModel(args[1]);
            if (loadedModel != null) {
                loadedModel.runSimulation();
            }
        }
        else {
            System.out.println("Invalid command");
        }
    }
}