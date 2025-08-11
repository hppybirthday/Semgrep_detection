import java.io.*;
import java.lang.reflect.Method;
import java.nio.file.*;
import java.util.*;

/**
 * 桌面游戏关卡加载器（存在路径遍历漏洞）
 * 使用反射实现元编程风格
 */
public class VulnerableGameLoader {
    // 游戏资源根目录
    private static final String BASE_DIR = "./game_resources/levels/";

    public static void main(String[] args) {
        try {
            // 模拟用户输入（攻击载荷："../../../../../etc/passwd"）
            String userInput = "../../../../../etc/passwd";
            
            // 通过反射动态调用加载方法（元编程）
            Class<?> loaderClass = Class.forName("VulnerableGameLoader");
            Method loadLevelMethod = loaderClass.getMethod("loadLevel", String.class);
            
            // 执行带漏洞的路径拼接
            Object result = loadLevelMethod.invoke(null, userInput);
            System.out.println("加载结果: " + result);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 动态加载关卡文件（包含路径遍历漏洞）
     * @param levelName 用户输入的关卡名称
     * @return 文件内容
     * @throws Exception
     */
    public static String loadLevel(String levelName) throws Exception {
        // 漏洞点：直接拼接用户输入到文件路径
        Path filePath = Paths.get(BASE_DIR + levelName);
        
        // 危险操作：未进行路径规范化检查
        if (!filePath.normalize().startsWith(Paths.get(BASE_DIR).normalize())) {
            throw new SecurityException("非法路径访问");
        }

        // 实际文件读取
        File file = new File(filePath.toString());
        if (!file.exists()) {
            return "关卡文件不存在";
        }

        // 使用缓冲读取
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("
");
            }
        }
        return content.toString();
    }

    // 模拟元编程的动态配置加载
    public static Map<String, Object> loadConfig(String configName) {
        Map<String, Object> config = new HashMap<>();
        config.put("version", 1.0);
        config.put("levelPath", BASE_DIR + configName);
        return config;
    }

    // 动态方法调用代理（示例）
    public static Object dynamicInvoke(String methodName, Object... args) {
        try {
            Method method = VulnerableGameLoader.class.getMethod(methodName, String.class);
            return method.invoke(null, args);
        } catch (Exception e) {
            throw new RuntimeException("调用失败: " + methodName, e);
        }
    }
}