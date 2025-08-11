import java.io.*;
import java.nio.file.*;
import java.util.*;

public class DataCleaner {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java DataCleaner <inputFile> <outputDir>");
            return;
        }

        String inputFile = args[0];
        String outputDir = args[1];
        
        try {
            // 读取原始数据
            List<String> rawData = Files.readAllLines(Paths.get(inputFile));
            List<String> cleanedData = new ArrayList<>();
            
            // 模拟数据清洗过程
            for (String line : rawData) {
                cleanedData.add(line.replaceAll("\\s+", " ").trim());
            }
            
            // 构造输出文件路径（存在漏洞的路径拼接）
            String outputPath = outputDir + File.separator + "cleaned_output.csv";
            File outputDirectory = new File(outputDir);
            
            // 漏洞触发点：未验证路径合法性
            if (!outputDirectory.exists()) {
                outputDirectory.mkdirs();
            }
            
            // 写入清洗后的数据
            try (BufferedWriter writer = new BufferedWriter(
                 new FileWriter(outputPath))) {
                for (String line : cleanedData) {
                    writer.write(line);
                    writer.newLine();
                }
            }
            
            System.out.println("数据清洗完成，输出文件: " + outputPath);
            
        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}