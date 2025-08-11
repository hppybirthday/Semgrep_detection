import java.io.*;
import java.util.Scanner;

public class Application {
    public static void main(String[] args) {
        DataProcessor processor = new DataProcessor();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("大数据处理系统 v1.0");
        System.out.print("请输入待处理文件名：");
        String filename = scanner.nextLine();
        
        System.out.println("开始处理数据...");
        try {
            processor.processData(filename);
        } catch (Exception e) {
            System.err.println("处理失败: " + e.getMessage());
        }
    }
}

class DataProcessor {
    public void processData(String filename) throws IOException, InterruptedException {
        // 使用外部工具进行数据转换（模拟大数据处理）
        String command = "python3 /opt/data_processing/scripts/transform_data.py --input " + filename + " --output /tmp/processed_data.csv";
        
        System.out.println("执行命令：" + command);
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("[输出] " + line);
        }
        
        int exitCode = process.waitFor();
        System.out.println("处理完成，退出码：" + exitCode);
    }
}