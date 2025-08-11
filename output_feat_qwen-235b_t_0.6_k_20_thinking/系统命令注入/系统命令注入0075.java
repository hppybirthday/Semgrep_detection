import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class BankCommandExecutor {
    private static final String BASE_CMD = "ls -l /bank/logs/";
    
    public static void main(String[] args) {
        try {
            // 模拟处理用户请求
            Map<String, String> params = new HashMap<>();
            params.put("accountId", "123456");
            params.put("logFilter", "; rm -rf /tmp/evil.sh"); // 恶意输入
            
            // 元编程方式调用执行方法
            Class<?> clazz = Class.forName("BankCommandExecutor");
            Method method = clazz.getMethod("executeCommand", Map.class);
            method.invoke(clazz.newInstance(), params);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void executeCommand(Map<String, String> params) throws IOException {
        String userInput = params.get("logFilter");
        // 漏洞点：直接拼接用户输入到系统命令
        String finalCmd = BASE_CMD + userInput;
        
        System.out.println("[DEBUG] Executing command: " + finalCmd);
        Process process = Runtime.getRuntime().exec("/bin/bash -c \\"" + finalCmd + "\\"");
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        BufferedReader errorReader = new BufferedReader(
            new InputStreamReader(process.getErrorStream()));
        
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        
        while ((line = errorReader.readLine()) != null) {
            System.err.println("ERROR: " + line);
        }
        
        try {
            int exitCode = process.waitFor();
            System.out.println("[DEBUG] Process exited with code: " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // 模拟银行系统日志处理接口
    public static class TransactionLogger {
        public void processLogQuery(String filter) {
            // 通过反射动态执行命令
            try {
                BankCommandExecutor executor = new BankCommandExecutor();
                Map<String, String> params = new HashMap<>();
                params.put("logFilter", filter);
                Method method = BankCommandExecutor.class.getMethod("executeCommand", Map.class);
                method.invoke(executor, params);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}