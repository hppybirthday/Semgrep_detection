import java.io.*;
import java.util.*;

// 高抽象建模风格：接口抽象+策略模式
interface LogProcessor {
    void processLog(String filename);
}

abstract class AbstractLogHandler {
    abstract void executeCompression(String filename);
}

class FileLogProcessor extends AbstractLogHandler implements LogProcessor {
    @Override
    void executeCompression(String filename) {
        try {
            // 危险的命令拼接（漏洞点）
            String cmd = "gzip -c /var/logs/" + filename + " > /var/archives/" + filename + ".gz";
            System.out.println("Executing: " + cmd);
            Runtime.getRuntime().exec("/bin/sh -c " + cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void processLog(String filename) {
        executeCompression(filename);
    }
}

class LogProcessingContext {
    private LogProcessor processor;

    public LogProcessingContext(LogProcessor processor) {
        this.processor = processor;
    }

    public void handleLog(String filename) {
        System.out.println("[System] Starting log processing...");
        processor.processLog(filename);
        System.out.println("[System] Processing complete.");
    }
}

public class BigDataPipeline {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter log filename to process: ");
        String filename = scanner.nextLine();
        
        // 初始化策略
        LogProcessor processor = new FileLogProcessor();
        LogProcessingContext context = new LogProcessingContext(processor);
        
        // 执行处理流程
        context.handleLog(filename);
    }
}