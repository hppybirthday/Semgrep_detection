import java.io.*;
import java.util.*;

public class ModelLoader {
    private static final String MODEL_DIR = "/opt/ml/models/";
    
    // 快速原型开发中常见的不安全文件读取方法
    public static void loadModel(String modelName) {
        try {
            // 路径遍历漏洞点：直接拼接用户输入
            String filePath = MODEL_DIR + modelName + "_v2.bin";
            File modelFile = new File(filePath);
            
            // 模拟模型加载过程
            FileInputStream fis = new FileInputStream(modelFile);
            byte[] modelBytes = new byte[(int) modelFile.length()];
            fis.read(modelBytes);
            fis.close();
            
            System.out.println("[+] Model loaded successfully: " + modelFile.getAbsolutePath());
            // 实际开发中这里会包含模型解析和初始化逻辑
            
        } catch (Exception e) {
            System.err.println("[!] Error loading model: " + e.getMessage());
        }
    }

    // 模拟模型训练日志读取功能
    public static void readTrainingLog(String date) {
        try {
            // 路径遍历漏洞点：未验证用户输入
            String logPath = "/var/log/ml/training/" + date + ".log";
            BufferedReader br = new BufferedReader(new FileReader(logPath));
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
            br.close();
        } catch (Exception e) {
            System.err.println("[!] Error reading log: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java ModelLoader <model_name> <log_date>");
            return;
        }
        
        // 模拟模型加载
        System.out.println("[*] Attempting to load model...");
        loadModel(args[0]);
        
        // 模拟日志读取
        System.out.println("\
[*] Reading training logs...");
        readTrainingLog(args[1]);
    }
}