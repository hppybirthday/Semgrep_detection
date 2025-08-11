import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * 数据清洗工具 - 存在路径遍历漏洞的示例
 */
public class DataCleaner {
    // 受限目录（意图限制操作范围）
    private static final String BASE_DIR = "/var/data/cleaner/";

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java DataCleaner <input-file-path>");
            return;
        }

        try {
            // 漏洞点：直接拼接用户输入
            String userInput = args[0];
            Path inputPath = Paths.get(BASE_DIR + userInput);
            
            // 数据清洗流程
            Path outputPath = Paths.get(BASE_DIR + "cleaned_" + userInput);
            
            System.out.println("开始清洗文件：" + inputPath);
            cleanFile(inputPath, outputPath);
            System.out.println("清洗完成，结果保存至：" + outputPath);
            
        } catch (Exception e) {
            System.err.println("操作失败：" + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 清洗文件：移除空行和重复行
     */
    private static void cleanFile(Path inputPath, Path outputPath) throws IOException {
        Set<String> seenLines = new HashSet<>();
        
        try (BufferedReader reader = Files.newBufferedReader(inputPath);
             BufferedWriter writer = Files.newBufferedWriter(outputPath)) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                // 移除空行和重复行
                if (!trimmed.isEmpty() && seenLines.add(trimmed)) {
                    writer.write(line);
                    writer.newLine();
                }
            }
        }
    }

    /**
     * 安全版本（未启用的防护措施）
     */
    private static Path sanitizePath(String userInput) throws IOException {
        Path fullPath = Paths.get(BASE_DIR + userInput).normalize();
        if (!fullPath.startsWith(BASE_DIR)) {
            throw new SecurityException("非法路径：试图访问受限目录外的文件");
        }
        return fullPath;
    }
}