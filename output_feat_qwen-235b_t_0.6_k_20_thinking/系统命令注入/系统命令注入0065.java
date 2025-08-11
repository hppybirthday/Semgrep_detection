import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class WebCrawlerController {
    public static void main(String[] args) throws Exception {
        // 模拟HTTP GET请求处理
        Map<String, String> params = new HashMap<>();
        params.put("host", "example.com; calc"); // 恶意输入
        
        // 元编程方式调用处理器
        String action = "commandJobHandler";
        Method handler = WebCrawlerController.class.getMethod(action, Map.class);
        handler.invoke(null, params);
    }

    public static void commandJobHandler(Map<String, String> params) {
        try {
            // 模拟爬虫任务参数解析
            String host = params.get("host");
            
            // 存在漏洞的命令构造（直接拼接用户输入）
            String[] cmd = {
                System.getProperty("os.name").toLowerCase().contains("win") 
                    ? "cmd.exe /c nslookup " + host
                    : "sh -c "nslookup " + host
            };
            
            // 执行系统命令
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            // 输出命令执行结果
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 模拟任务参数解析器（简化版）
    static class sysJob {
        static String getMethodParamsValue(String param, Map<String, String> params) {
            return params.get(param);
        }
    }
}