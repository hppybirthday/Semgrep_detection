import java.io.*;
import java.nio.file.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class ModelLoader {
    // 模拟机器学习模型加载接口
    @GetMapping("/loadModel")
    public String loadModel(@RequestParam String modelName) {
        try {
            // 漏洞点：直接拼接用户输入到文件路径
            String basePath = "/opt/ml/models/";
            String modelPath = basePath + modelName + ".bin";
            
            // 模拟模型加载过程
            File modelFile = new File(modelPath);
            if (!modelFile.exists()) {
                return "Model not found";
            }
            
            // 漏洞利用示例：读取敏感文件
            if (modelPath.contains("passwd")) {
                BufferedReader reader = new BufferedReader(
                    new FileReader(modelFile)
                );
                StringBuilder content = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\\\
");
                }
                return content.toString();
            }
            
            // 正常模型加载逻辑（模拟）
            return String.format("Loaded model '%s' (%d KB)", 
                modelName, modelFile.length()/1024);
            
        } catch (Exception e) {
            return "Error loading model: " + e.getMessage();
        }
    }
    
    // 模拟模型训练数据加载
    private byte[] loadTrainingData(String dataPath) throws IOException {
        // 漏洞传播：将用户输入路径直接传递给文件操作
        return Files.readAllBytes(Paths.get(dataPath));
    }
    
    public static void main(String[] args) {
        // 模拟启动代码（实际应由Spring容器管理）
        System.out.println("ML Model Server started");
    }
}