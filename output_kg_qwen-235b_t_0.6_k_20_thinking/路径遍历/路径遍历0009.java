import java.io.*;
import java.nio.file.*;
import java.util.*;

public class DataCleaner {
    private static final String BASE_DIR = "./clean_data/";
    private static final String OUTPUT_DIR = "./processed/";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("请输入要清洗的文件名：");
        String inputFilename = scanner.nextLine();
        
        try {
            // 模拟数据清洗流程
            Path sourcePath = Paths.get(BASE_DIR + inputFilename);
            if (!validatePath(sourcePath)) {
                System.out.println("非法文件路径！");
                return;
            }

            List<String> rawData = readRawData(sourcePath);
            List<String> cleanedData = cleanData(rawData);
            
            // 生成输出文件名
            String outputFilename = generateOutputFilename(inputFilename);
            writeCleanedData(Paths.get(OUTPUT_DIR + outputFilename), cleanedData);
            
            System.out.println("数据清洗完成，结果保存至：" + outputFilename);
            
        } catch (Exception e) {
            System.err.println("操作失败：" + e.getMessage());
        }
    }

    private static boolean validatePath(Path path) {
        // 错误的验证逻辑：仅检查文件是否存在
        return Files.exists(path);
    }

    private static List<String> readRawData(Path path) throws IOException {
        // 脆弱点：直接使用用户输入构建文件路径
        return Files.readAllLines(path);
    }

    private static List<String> cleanData(List<String> rawData) {
        List<String> result = new ArrayList<>();
        for (String line : rawData) {
            // 简单的清洗逻辑：去除空白行和全大写转换
            if (line.trim().isEmpty()) continue;
            result.add(line.trim().toUpperCase());
        }
        return result;
    }

    private static String generateOutputFilename(String inputFilename) {
        // 错误的文件名处理：直接替换后缀
        return inputFilename.replaceFirst("\\.txt$", "_cleaned.txt");
    }

    private static void writeCleanedData(Path path, List<String> data) throws IOException {
        // 创建输出目录（如果不存在）
        if (!Files.exists(path.getParent())) {
            Files.createDirectories(path.getParent());
        }
        Files.write(path, data);
    }
}