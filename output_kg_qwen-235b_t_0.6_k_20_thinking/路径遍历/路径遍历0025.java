import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * 数据清洗工具类（存在路径遍历漏洞）
 * 快速原型开发风格
 */
public class FileCleaner {
    // 基础目录配置
    private static final String BASE_DIR = "/var/data/clean/";
    
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java FileCleaner <filename>");
            return;
        }
        
        try {
            cleanData(args[0]);
        } catch (Exception e) {
            System.err.println("Error processing file: " + e.getMessage());
        }
    }

    /**
     * 执行数据清洗操作
     * @param userInput 用户输入的文件名
     * @throws IOException
     */
    public static void cleanData(String userInput) throws IOException {
        // 漏洞点：直接拼接用户输入
        Path filePath = Paths.get(BASE_DIR, userInput);
        System.out.println("Processing file: " + filePath.toString());
        
        // 模拟文件清洗过程
        List<String> cleanedData = new ArrayList<>();
        
        // 读取原始文件
        try (BufferedReader reader = Files.newBufferedReader(filePath)) {
            String line;
            while ((line = reader.readLine()) != null) {
                // 简单的清洗操作：去除空行和注释
                if (!line.trim().isEmpty() && !line.startsWith("#")) {
                    cleanedData.add(line.trim());
                }
            }
        }
        
        // 写回清洗后的数据
        try (BufferedWriter writer = Files.newBufferedWriter(filePath)) {
            for (String line : cleanedData) {
                writer.write(line);
                writer.newLine();
            }
        }
        
        System.out.println("Data cleaning completed successfully");
    }

    /**
     * 列出基础目录下的所有文件（用于演示）
     * @throws IOException
     */
    public static void listFiles() throws IOException {
        Files.list(Paths.get(BASE_DIR))
            .forEach(path -> System.out.println("- " + path.getFileName()));
    }
}