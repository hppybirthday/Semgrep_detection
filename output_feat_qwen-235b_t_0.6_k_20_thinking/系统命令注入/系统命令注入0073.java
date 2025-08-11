import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

// 模拟大数据处理中的日志分析模块
class LogProcessor {
    // 模拟处理日志文件路径的接口
    public void processLogFile(String filePath) {
        try {
            // 漏洞点：直接拼接用户输入构造命令
            String command = "gunzip -c " + filePath + " | grep -i 'error'";
            System.out.println("[DEBUG] Executing command: " + command);
            
            // 使用Runtime执行系统命令
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 模拟用户输入处理类
class InputHandler {
    private LogProcessor logProcessor;

    public InputHandler() {
        this.logProcessor = new LogProcessor();
    }

    // 模拟WebSocket消息处理方法
    public void handleMessage(String userInput) {
        // 直接传递用户输入到命令执行层
        logProcessor.processLogFile(userInput);
    }
}

// 主程序入口
public class Main {
    public static void main(String[] args) {
        // 模拟WebSocket服务端接收消息
        InputHandler handler = new InputHandler();
        
        // 模拟用户输入（可能包含恶意负载）
        if (args.length > 0) {
            System.out.println("Processing user input: " + args[0]);
            handler.handleMessage(args[0]);
        } else {
            System.out.println("Usage: java Main \\"<file_path>\\"");
            System.out.println("Example: java Main \\"/var/logs/app.log\\"");
        }
    }
}