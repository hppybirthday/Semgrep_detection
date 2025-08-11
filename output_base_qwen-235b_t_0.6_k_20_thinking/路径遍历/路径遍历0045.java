import java.io.*;
import java.lang.reflect.*;
import java.util.*;

// 模拟数学建模框架
abstract class ModelProcessor {
    public abstract void execute(String filename);
}

// 动态模型加载器
class ModelLoader {
    public static ModelProcessor loadModel(String modelName) {
        try {
            Class<?> clazz = Class.forName("com.example.math.Model_" + modelName);
            return (ModelProcessor) clazz.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load model: " + modelName, e);
        }
    }
}

// 核心数学模型
class Model_Core extends ModelProcessor {
    @Override
    public void execute(String filename) {
        try {
            // 漏洞点：未验证用户输入
            String basePath = "/var/math_models/";
            String fullPath = basePath + filename;
            
            // 模拟模型计算
            File file = new File(fullPath);
            if (!file.exists()) {
                System.out.println("Model file not found: " + fullPath);
                return;
            }
            
            // 漏洞触发点：实际读取任意文件
            byte[] data = new byte[(int) file.length()];
            new FileInputStream(file).read(data);
            System.out.println("Loaded model data length: " + data.length);
            
            // 模拟数值计算
            double result = 0;
            for (byte b : data) {
                result += Math.sin(b);
            }
            System.out.println("Model execution result: " + result);
            
        } catch (Exception e) {
            System.out.println("Model execution error: " + e.getMessage());
        }
    }
}

// 元编程驱动类
public class MathModelFramework {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java MathModelFramework <model_name> <file_path>");
            return;
        }
        
        // 反射调用模型
        String modelName = args[0];
        String filePath = args[1];
        
        ModelProcessor model = ModelLoader.loadModel(modelName);
        model.execute(filePath);
    }
}