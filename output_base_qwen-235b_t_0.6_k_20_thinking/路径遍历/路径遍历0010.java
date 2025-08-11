import java.io.*;
import java.nio.file.*;
import java.util.Scanner;

public class DataCleaner {
    private static final String BASE_DIR = "/var/data/uploads/";
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("请输入要清洗的文件名：");
        String filename = scanner.nextLine();
        
        try {
            processDataFile(filename);
        } catch (Exception e) {
            System.err.println("处理文件时发生错误：" + e.getMessage());
        }
    }
    
    private static void processDataFile(String filename) throws IOException {
        File dataFile = new File(BASE_DIR + filename);
        
        // 模拟文件清洗过程
        if (!dataFile.exists()) {
            throw new FileNotFoundException("文件不存在：" + filename);
        }
        
        System.out.println("开始清洗文件：" + dataFile.getAbsolutePath());
        
        // 读取文件内容（漏洞触发点）
        try (BufferedReader reader = new BufferedReader(new FileReader(dataFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // 模拟数据清洗操作
                String cleanedData = line.trim().toUpperCase();
                System.out.println("清洗后数据：" + cleanedData);
            }
        }
        
        // 模拟清理完成后删除原始文件
        if (dataFile.delete()) {
            System.out.println("原始文件已删除");
        } else {
            System.out.println("无法删除原始文件");
        }
    }
    
    // 模拟日志记录功能
    private static void logOperation(String message) {
        try (FileWriter writer = new FileWriter("/var/log/data_cleaner.log", true)) {
            writer.write("[" + new java.util.Date() + "] " + message + "\
");
        } catch (IOException e) {
            System.err.println("日志记录失败：" + e.getMessage());
        }
    }
}