import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class WebCrawler {
    // 模拟爬虫下载文件并执行系统命令处理
    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("Usage: java WebCrawler <file_path>");
            return;
        }
        
        String userInput = args[0];
        try {
            processPDFFile(userInput);
        } catch (Exception e) {
            System.err.println("Error processing file: " + e.getMessage());
        }
    }

    /**
     * 模拟处理PDF文件的业务逻辑
     * 使用用户输入作为文件路径直接拼接系统命令
     * 存在系统命令注入风险
     */
    private static void processPDFFile(String filePath) throws IOException {
        // 假设使用magic-pdf工具进行PDF处理
        String command = "magic-pdf " + filePath;  // 漏洞点：直接拼接用户输入
        
        System.out.println("Executing command: " + command);
        
        // 使用Runtime执行系统命令
        Process process = Runtime.getRuntime().exec(command);  // 漏洞触发点
        
        // 处理命令执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("Output: " + line);
        }
        
        // 等待命令执行完成
        try {
            int exitCode = process.waitFor();
            System.out.println("Command exited with code " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted");
        }
    }

    // 模拟网络爬虫文件下载功能
    private static String simulateDownload() {
        // 实际场景中可能从远程URL下载文件
        return "/tmp/crawled_data/" + System.currentTimeMillis() + ".pdf";
    }
}