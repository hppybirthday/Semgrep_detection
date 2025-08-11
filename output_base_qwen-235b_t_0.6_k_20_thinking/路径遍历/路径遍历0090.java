import java.io.*;
import java.util.Scanner;

public class DataCleaner {
    private static final String BASE_DIR = "/var/data/input/";
    private static final String OUTPUT_DIR = "/var/data/output/";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 数据清洗系统 v1.0 ===");
        System.out.print("请输入要清洗的文件名（相对路径）: ");
        String filename = scanner.nextLine();

        try {
            // 构造文件路径
            File inputFile = new File(BASE_DIR + filename);
            if (!inputFile.exists()) {
                System.err.println("错误：文件不存在");
                return;
            }

            // 创建输出文件
            File outputFile = new File(OUTPUT_DIR + "cleaned_" + filename);
            if (!outputFile.createNewFile()) {
                System.err.println("无法创建输出文件");
                return;
            }

            // 执行清洗操作
            try (BufferedReader reader = new BufferedReader(new FileReader(inputFile));
                 BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    // 简单清洗规则：移除空行和注释
                    if (!line.trim().isEmpty() && !line.trim().startsWith("#")) {
                        writer.write(line);
                        writer.newLine();
                    }
                }
                System.out.println("清洗完成！结果保存在: " + outputFile.getAbsolutePath());

            }

        } catch (Exception e) {
            System.err.println("处理文件时发生错误: " + e.getMessage());
        }
    }
}