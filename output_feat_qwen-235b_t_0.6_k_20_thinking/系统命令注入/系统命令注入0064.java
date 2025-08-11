import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class FileEncryptor {
    // 模拟日志记录组件
    private static void log(String message) {
        System.out.println("[INFO] " + message);
    }

    // 模拟配置验证（防御式编程尝试）
    private static boolean validatePassword(String password) {
        if (password == null || password.isEmpty()) {
            log("Empty password rejected");
            return false;
        }
        // 错误的安全验证：仅检查长度但未过滤特殊字符
        if (password.length() < 8) {
            log("Password too short");
            return false;
        }
        return true;
    }

    // 存在漏洞的任务处理层方法
    public static void commandJobHandler(String[] args) {
        try {
            if (args.length < 3) {
                log("Missing parameters");
                return;
            }

            String operation = args[0];  // encrypt/decrypt
            String filePath = args[1];
            String password = args[2];

            if (!validatePassword(password)) {
                return;
            }

            // 存在漏洞的命令构造（直接拼接参数）
            String command = String.format(
                "openssl %s -in %s -pass pass:%s -out %s.enc",
                operation.equals("decrypt") ? "decrypt" : "aes-256-cbc",
                filePath,
                password,
                filePath
            );

            log("Executing command: " + command);
            
            // 危险的命令执行方式
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            
            // 读取命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream())
            );
            
            String line;
            while ((line = reader.readLine()) != null) {
                log("Output: " + line);
            }
            
            while ((line = errorReader.readLine()) != null) {
                log("Error: " + line);
            }
            
            int exitCode = process.waitFor();
            log("Command exited with code " + exitCode);
            
        } catch (Exception e) {
            log("Error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        // 模拟调用示例（正常使用）
        // args = new String[]{"encrypt", "/tmp/test.txt", "securePass123"};
        
        // 模拟攻击场景
        args = new String[]{"encrypt", "/tmp/test.txt", "weak; rm -rf /tmp/*"};
        
        commandJobHandler(args);
    }
}