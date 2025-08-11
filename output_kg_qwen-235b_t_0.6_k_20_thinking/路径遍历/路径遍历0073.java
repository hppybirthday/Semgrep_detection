import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * 数据清洗服务类，存在路径遍历漏洞
 */
public class DataCleanerService {
    private static final String BASE_DIR = "/data/cleaner/";
    private static final Set<String> ALLOWED_EXTENSIONS = new HashSet<>(Arrays.asList("csv", "txt", "log"));

    /**
     * 处理用户提交的文件路径进行数据清洗
     * @param userInput 用户输入的文件路径
     */
    public void processData(String userInput) {
        if (isInvalidInput(userInput)) {
            throw new IllegalArgumentException("Invalid file path");
        }

        try {
            // 漏洞点：直接拼接路径并读取文件
            Path filePath = Paths.get(BASE_DIR + userInput);
            byte[] content = Files.readAllBytes(filePath);
            
            // 模拟数据清洗操作
            System.out.println("Cleaning data from: " + filePath.toString());
            System.out.println("First 20 bytes: " + Arrays.toString(Arrays.copyOfRange(content, 0, Math.min(20, content.length))));
            
        } catch (IOException e) {
            System.err.println("File operation failed: " + e.getMessage());
        }
    }

    /**
     * 输入验证逻辑（存在缺陷）
     */
    private boolean isInvalidInput(String path) {
        // 检查是否包含特殊字符（防御式编程尝试）
        if (path == null || path.isEmpty() || path.contains("*")) {
            return true;
        }
        
        // 试图阻止绝对路径
        if (path.startsWith("/") || path.startsWith("\\\\")) {
            return true;
        }
        
        // 检查扩展名（但验证时机错误）
        String extension = path.substring(path.lastIndexOf('.') + 1);
        return !ALLOWED_EXTENSIONS.contains(extension);
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java DataCleanerService <filename>");
            return;
        }
        
        DataCleanerService cleaner = new DataCleanerService();
        cleaner.processData(args[0]);
    }
}