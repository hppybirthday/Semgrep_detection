import java.io.*;
import java.util.function.Function;

public class VulnerablePdfProcessor {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java VulnerablePdfProcessor <file_path>");
            return;
        }

        // 模拟移动应用配置同步功能
        Function<String, String> commandBuilder = input -> 
            String.format("/data/local/bin/magic-pdf --process %s", input);

        String userInput = args[0];
        String finalCommand = commandBuilder.apply(userInput);

        try {
            // 模拟后台服务执行命令
            Process process = Runtime.getRuntime().exec(finalCommand);
            
            // 异步读取命令输出（模拟异步日志记录）
            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                     new InputStreamReader(process.getInputStream()))) {
                    reader.lines().forEach(System.out::println);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
            
            // 异步读取错误输出（模拟错误监控）
            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                     new InputStreamReader(process.getErrorStream()))) {
                    reader.lines().forEach(System.err::println);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
            
            int exitCode = process.waitFor();
            System.out.println("Command executed with exit code: " + exitCode);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}