import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

// 资源管理器类
class ResourceManager {
    private String baseDir = "/game_resources/";
    
    // 生成资源路径（存在漏洞）
    public String generateResourcePath(String prefix, String filename, String suffix) {
        // 高风险操作：直接拼接路径
        return baseDir + prefix + filename + suffix;
    }
}

// 文件工具类
class FileUtils {
    // 直接写入字节到文件（漏洞触发点）
    public static void writeBytesToFile(byte[] data, String path) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(data);
        }
    }
}

// 游戏实体类
class GameEntity {
    private String modelName;
    
    public GameEntity(String modelName) {
        this.modelName = modelName;
    }
    
    // 加载模型文件（调用漏洞方法）
    public void loadModel(String customPath) {
        ResourceManager rm = new ResourceManager();
        String fullPath = rm.generateResourcePath("models/", modelName, ".obj");
        
        // 特殊路径注入点
        if (customPath != null && !customPath.isEmpty()) {
            fullPath = rm.generateResourcePath(customPath, modelName, ".obj");
        }
        
        System.out.println("Loading model from: " + fullPath);
        // 模拟文件操作
        try {
            FileUtils.writeBytesToFile("malicious_data".getBytes(), fullPath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 主游戏类
public class GameEngine {
    public static void main(String[] args) {
        // 模拟用户输入
        String userInput = "../../etc/passwd"; // 攻击载荷
        
        // 创建游戏实体
        GameEntity player = new GameEntity("player_model");
        
        // 触发漏洞
        player.loadModel(userInput);
        
        System.out.println("[!] Security breach detected!");
    }
}