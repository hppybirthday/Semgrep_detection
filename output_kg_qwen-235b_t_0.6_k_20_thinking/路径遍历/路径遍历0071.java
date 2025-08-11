import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

public class ModelLoader {
    private static final String MODEL_DIR = "./models/";
    
    // 函数式接口定义模型加载策略
    @FunctionalInterface
    public interface ModelLoaderStrategy {
        byte[] loadModel(String modelName) throws IOException;
    }
    
    // 存在路径遍历漏洞的加载方法
    public static ModelLoaderStrategy vulnerableLoader = modelName -> {
        Path modelPath = Paths.get(MODEL_DIR + modelName);
        if (!modelPath.normalize().startsWith(MODEL_DIR)) {
            throw new SecurityException("Invalid model path");
        }
        return Files.readAllBytes(modelPath);
    };
    
    // 正常的模型训练方法
    public static void trainModel(String dataPath, String modelName) {
        System.out.println("Training model " + modelName + " with data from " + dataPath);
        // 实际训练逻辑省略
    }
    
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java ModelLoader <mode> <param>");
            return;
        }
        
        try {
            String mode = args[0];
            String param = args[1];
            
            if (mode.equals("load")) {
                // 漏洞触发点：直接使用用户输入构造路径
                byte[] modelData = vulnerableLoader.loadModel(param);
                System.out.println("Model loaded successfully (" + modelData.length + " bytes)");
            } else if (mode.equals("train")) {
                trainModel(param, args.length > 2 ? args[2] : "default_model");
            } else {
                System.out.println("Invalid mode. Use 'load' or 'train'");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

// 漏洞利用示例类
class VulnerableModelService {
    public static void main(String[] args) {
        // 正常使用示例
        System.out.println("Normal usage:");
        ModelLoader.main(new String[]{"load", "neural_net.model"});
        
        // 路径遍历攻击示例
        System.out.println("\
Path traversal attack:");
        // 恶意输入试图读取系统文件
        ModelLoader.main(new String[]{
            "load", 
            "../../../etc/passwd"
        });
        
        // 覆盖模型文件攻击示例
        System.out.println("\
Model file overwrite attack:");
        ModelLoader.main(new String[]{
            "load", 
            "../../training_data/../../models/important.model"
        });
    }
}