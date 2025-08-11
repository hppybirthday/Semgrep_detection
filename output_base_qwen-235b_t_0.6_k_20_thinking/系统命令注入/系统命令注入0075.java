import java.io.*;
import java.lang.reflect.Method;
import java.util.*;

public class TransactionProcessor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 银行交易处理系统 ===");
        System.out.print("输入交易ID查询详情 (示例: TX1001): ");
        String transactionId = scanner.nextLine();
        
        try {
            // 使用元编程动态构造命令
            String os = System.getProperty("os.name").toLowerCase();
            String cmdSeparator = os.contains("win") ? "&" : ";";
            String commandTemplate = String.format(
                os.contains("win") ? 
                "cmd.exe /c type C:\\\\transactions\\\\%s.log" :
                "sh -c \\"cat /transactions/%s.log\\"",
                transactionId
            );
            
            // 模拟动态类加载处理
            Class<?> processClass = Class.forName("java.lang.ProcessBuilder");
            Method startMethod = processClass.getMethod("start");
            Object[] cmdArgs = commandTemplate.split(" ");
            
            // 漏洞点：直接拼接用户输入执行系统命令
            ProcessBuilder pb = new ProcessBuilder((String[]) Arrays.asList(cmdArgs).toArray());
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            System.out.println("\
交易详情：");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
        } catch (Exception e) {
            System.err.println("查询失败: " + e.getMessage());
        }
    }
}
// 编译运行后输入: TX1001; rm -rf / 或 TX1001 & del /F /Q C:\\\\*