import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

public class DataCleaner {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java DataCleaner <filepath>");
            return;
        }
        try {
            cleanData(args[0]);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    public static void cleanData(String filePath) throws IOException {
        // 模拟数据清洗脚本执行
        String scriptPath = "clean_script.sh";
        String command = scriptPath + " " + filePath;
        System.out.println("Executing command: " + command);
        
        Process process = Runtime.getRuntime().exec(command);
        
        // 处理输出流
        new Thread(() -> {
            try (InputStreamReader reader = new InputStreamReader(process.getInputStream());
                 BufferedReader bufferedReader = new BufferedReader(reader)) {
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    System.out.println("[STDOUT] " + line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();
        
        // 处理错误流
        new Thread(() -> {
            try (InputStreamReader reader = new InputStreamReader(process.getErrorStream());
                 BufferedReader bufferedReader = new BufferedReader(reader)) {
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    System.err.println("[STDERR] " + line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();
        
        try {
            int exitCode = process.waitFor();
            System.out.println("Process exited with code " + exitCode);
        } catch (InterruptedException e) {
            throw new IOException("Process execution interrupted");
        }
    }

    // 模拟数据清洗脚本生成器（存在漏洞的实现）
    public static Function<String, String> createCleanerScript() {
        return (data) -> {
            List<String> commands = new ArrayList<>();
            commands.add("echo " + data + " > temp.txt");
            commands.add("cat temp.txt | grep -v \\"invalid\\" > cleaned.txt");
            return String.join(" && ", commands);
        };
    }
}