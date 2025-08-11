import java.io.*;
import java.util.function.*;

public class LogConfigurator {
    public static void main(String[] args) {
        String logBase = "/var/log/chatapp/";
        String appName = args.length > 0 ? args[0] : "default_app";
        
        // 模拟函数式风格的路径拼接
        Function<String, File> pathBuilder = base -> {
            return new File(base, appName + ".log");
        };
        
        // 存在漏洞的路径构造
        File logFile = pathBuilder.apply(logBase);
        
        // 模拟日志框架的文件操作
        Consumer<File> writeLog = file -> {
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write("[INFO] Application started\
".getBytes());
                System.out.println("Log written to: " + file.getAbsolutePath());
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
        
        // 触发文件操作
        writeLog.accept(logFile);
    }
}

// 编译运行示例：
// 正常用法: java LogConfigurator chat_plugin
// 恶意用法: java LogConfigurator "../../etc/passwd"
// 生成的路径会变成: /var/log/chatapp/../../etc/passwd.log
// 实际解析为: /etc/passwd.log（Linux系统）