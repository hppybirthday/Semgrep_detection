import java.io.*;
import java.lang.reflect.Method;
import java.util.*;

// 桌面游戏资源管理器（存在路径遍历漏洞）
public class GameManager {
    private static final String BASE_PATH = "/var/game/resources/";
    
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java GameManager <resourcePath>");
            return;
        }
        
        // 模拟元编程动态调用
        Class<?> clazz = Class.forName("ResourceLoader");
        Method method = clazz.getMethod("loadResource", String.class);
        Object result = method.invoke(clazz.newInstance(), args[0]);
        System.out.println("Resource content: " + result);
    }
}

class ResourceLoader {
    public String loadResource(String bizPath) throws IOException {
        // 路径拼接元操作
        String fullPath = String.format("%s%s%s", 
            BASE_PATH, File.separator, bizPath);
            
        // 文件操作元封装
        return (String) FileUtil.invokeOperation("read", fullPath);
    }
}

class FileUtil {
    public static Object invokeOperation(String op, String path) throws IOException {
        File file = new File(path);
        
        switch (op) {
            case "read":
                if (!file.exists()) return "Not found";
                // 存在漏洞的文件读取
                return readFileContent(file);
            case "delete":
                // 模拟文件删除接口
                return file.delete() ? "Deleted" : "Failed";
            default:
                throw new IllegalArgumentException("Invalid operation");
        }
    }
    
    private static String readFileContent(File file) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }
}