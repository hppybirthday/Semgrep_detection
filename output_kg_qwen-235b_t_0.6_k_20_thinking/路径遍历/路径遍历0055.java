import static spark.Spark.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class MLModelServer {
    // 模拟机器学习模型服务
    private static final String BASE_DIR = "/data/ml_datasets/";

    public static void main(String[] args) {
        port(8080);
        
        // 模型训练接口
        post("/train", (req, res) -> {
            String filePath = req.queryParams("dataset");
            if (filePath == null || filePath.isEmpty()) {
                return "Missing dataset path";
            }
            
            try {
                // 路径遍历漏洞点：直接拼接用户输入
                File dataset = new File(BASE_DIR + filePath);
                
                // 模拟读取数据集
                List<String> data = Files.readAllLines(dataset.toPath());
                
                // 模拟训练过程（简化处理）
                String response = String.format("Training completed with %d records from %s\
First row: %s",
                    data.size(), 
                    dataset.getAbsolutePath(),
                    data.isEmpty() ? "empty" : data.get(0));
                
                return response;
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        });
        
        // 模型预测接口
        post("/predict", (req, res) -> {
            String modelPath = req.queryParams("model");
            if (modelPath == null || modelPath.isEmpty()) {
                return "Missing model path";
            }
            
            try {
                // 路径遍历漏洞点：未验证用户输入
                File modelFile = new File("/models/" + modelPath);
                
                // 模拟加载模型（简化处理）
                byte[] modelData = Files.readAllBytes(modelFile.toPath());
                
                return String.format("Loaded model from %s (size: %d bytes)",
                    modelFile.getAbsolutePath(), modelData.length);
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        });
        
        System.out.println("ML Server started at http://localhost:8080");
    }
}