import java.io.*;
import java.nio.file.*;
import java.util.Scanner;

public class ModelLoader {
    // 模拟机器学习模型加载器
    private static final String BASE_DIR = "models/";
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter model name to load: ");
        String modelName = scanner.nextLine();
        
        try {
            byte[] modelData = loadModel(modelName);
            System.out.println("Model loaded successfully (" + modelData.length + " bytes)");
            // 模拟模型预测
            System.out.println("Predicting... Result: 42");
        } catch (Exception e) {
            System.err.println("Error loading model: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 漏洞点：不安全的路径拼接
     * @param modelName 用户输入的模型名称
     * @return 模型文件的字节数据
     * @throws IOException
     */
    public static byte[] loadModel(String modelName) throws IOException {
        // 路径拼接时未校验用户输入
        File modelFile = new File(BASE_DIR + modelName);
        
        // 漏洞验证：显示实际访问的路径
        System.out.println("[DEBUG] Accessing path: " + modelFile.getAbsolutePath());
        
        // 检查文件是否存在
        if (!modelFile.exists()) {
            throw new FileNotFoundException("Model file not found: " + modelName);
        }
        
        // 读取模型文件
        return Files.readAllBytes(modelFile.toPath());
    }
    
    // 模拟保存模型的漏洞方法
    public static void saveModel(String modelName, byte[] data) throws IOException {
        // 相同漏洞存在于保存操作
        File modelFile = new File(BASE_DIR + modelName);
        Files.write(modelFile.toPath(), data);
    }
}