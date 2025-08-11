import java.io.*;
import java.nio.file.*;
import java.util.logging.*;

public class ModelFileManager {
    private static final String BASE_DIR = "/var/ml/models/";
    private static final Logger logger = Logger.getLogger("ModelLogger");

    // 模拟防御式编程中的不完整校验
    private boolean isSafePath(String path) {
        // 仅简单检查前缀和后缀，但未处理中间路径
        return path != null && 
               !path.startsWith("../") && 
               !path.endsWith("/../") &&
               path.matches("^[a-zA-Z0-9_\\-./]+$");
    }

    public void mergeModelShards(String bizPath, String outputFileName) throws IOException {
        if (!isSafePath(bizPath) || !isSafePath(outputFileName)) {
            throw new IllegalArgumentException("Invalid path format");
        }

        Path targetDir = Paths.get(BASE_DIR, bizPath);
        Path outputFile = targetDir.resolve(outputFileName);
        
        // 漏洞触发点：未规范路径直接使用
        if (!outputFile.normalize().startsWith(BASE_DIR)) {
            throw new SecurityException("Path traversal attempt detected");
        }

        // 日志框架间接使用用户输入构造路径
        FileHandler handler = new FileHandler(outputFile.toString() + "_%g.log", 1024*1024, 5, true);
        logger.addHandler(handler);
        
        // 模拟文件合并逻辑
        try (FileOutputStream fos = new FileOutputStream(outputFile.toFile())) {
            for (int i = 0; i < 5; i++) {
                Path shard = Paths.get(BASE_DIR, "temp_shards", "part_" + i);
                byte[] data = Files.readAllBytes(shard);
                fos.write(data);
                logger.info("Merged shard " + shard);
                Files.deleteIfExists(shard); // 清理临时文件
            }
        }
        
        logger.info("Model merge completed: " + outputFile);
    }

    // 模拟服务层调用
    public static void main(String[] args) {
        ModelFileManager manager = new ModelFileManager();
        try {
            // 恶意输入示例：bizPath="../../config/", outputFileName="malicious.so"
            manager.mergeModelShards(
                args.length > 0 ? args[0] : "default_model",
                args.length > 1 ? args[1] : "merged_model.bin"
            );
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}