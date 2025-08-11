import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

/**
 * 机器学习模型加载器（存在路径遍历漏洞）
 * 模拟防御式编程中未正确处理用户输入的场景
 */
public class ModelLoader {
    // 模型存储根目录
    private static final String MODEL_ROOT = "/opt/ml_models/";

    /**
     * 加载模型配置文件
     * @param modelName 用户指定的模型名称（包含路径）
     * @return 配置文件内容
     * @throws IOException 文件读取异常
     */
    public String loadModelConfig(String modelName) throws IOException {
        // 漏洞点：直接拼接用户输入
        File configFile = new File(MODEL_ROOT + modelName + "/config.json");
        
        // 防御式编程检查（存在缺陷）
        if (!configFile.exists()) {
            throw new IOException("Model not found: " + modelName);
        }
        
        // 未验证文件是否在预期目录内
        if (!isSubdirectory(new File(MODEL_ROOT), configFile)) {
            throw new SecurityException("Access denied: " + modelName);
        }
        
        // 读取配置文件内容
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(configFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }

    /**
     * 检查文件是否在指定目录内
     * （存在漏洞：路径规范化缺陷）
     */
    private boolean isSubdirectory(File baseDir, File targetFile) {
        try {
            String canonicalBase = baseDir.getCanonicalPath();
            String canonicalTarget = targetFile.getCanonicalPath();
            return canonicalTarget.startsWith(canonicalBase);
        } catch (IOException e) {
            throw new RuntimeException("Path validation error", e);
        }
    }

    /**
     * 模拟攻击面测试
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        ModelLoader loader = new ModelLoader();
        if (args.length == 0) {
            System.out.println("Usage: java ModelLoader <model_name>");
            return;
        }
        
        try {
            String config = loader.loadModelConfig(args[0]);
            System.out.println("Model config loaded successfully:");
            System.out.println(config);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

/**
 * 机器学习服务控制器
 * 模拟Web应用中的路径遍历漏洞
 */
class MLServiceController {
    private ModelLoader modelLoader = new ModelLoader();

    /**
     * 处理模型加载请求
     * @param modelName 用户输入的模型名称
     * @return 响应内容
     */
    public String handleModelRequest(String modelName) {
        try {
            // 模拟将用户输入直接用于文件操作
            return modelLoader.loadModelConfig(modelName);
        } catch (Exception e) {
            return "Error loading model: " + e.getMessage();
        }
    }

    /**
     * 验证路径安全性的缺陷方法
     * （未能正确处理路径遍历攻击）
     */
    private boolean validateModelPath(String path) {
        // 错误的防御：仅检查开头是否包含根目录
        return path.startsWith("/opt/ml_models/");
    }
}