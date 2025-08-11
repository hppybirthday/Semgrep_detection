import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * 数学模型参数加载器（存在路径遍历漏洞）
 * 使用反射实现元编程特性
 */
public class ModelParameterLoader {
    private static final Logger logger = Logger.getLogger("ModelParameterLoader");
    private static final String BASE_DIR = "/var/math_models/params";

    // 动态方法调用处理器
    public static Object invokeMethod(String methodName, Object... args) {
        try {
            Method method = ModelParameterLoader.class.getMethod(methodName, 
                Arrays.stream(args).map(Object::getClass).toArray(Class[]::new));
            return method.invoke(null, args);
        } catch (Exception e) {
            logger.severe("方法调用失败: " + e.getMessage());
            return null;
        }
    }

    // 参数文件读取核心方法（存在漏洞）
    public static List<String> loadModelParameters(String modelName, String paramName) {
        try {
            // 路径构造存在漏洞
            Path paramPath = Paths.get(BASE_DIR, modelName, paramName + ".param");
            logger.info("正在加载参数文件: " + paramPath.toString());
            
            // 存在漏洞的路径遍历点
            if (!paramPath.normalize().startsWith(BASE_DIR)) {
                throw new SecurityException("非法路径访问");
            }
            
            return Files.readAllLines(paramPath);
        } catch (IOException e) {
            logger.warning("参数加载失败: " + e.getMessage());
            return List.of("默认参数值");
        }
    }

    // 参数验证方法（存在缺陷）
    public static boolean validateParamName(String paramName) {
        // 错误的过滤方式
        return !paramName.contains("..") && 
               paramName.matches("[a-zA-Z0-9_\\\\-]+.param");
    }

    // 动态参数处理方法
    public static String processParameter(String input) {
        // 使用反射调用核心方法
        List<String> result = (List<String>) invokeMethod("loadModelParameters", 
            "default_model", input);
        return String.join(", ", result);
    }

    // 模型参数缓存机制
    public static class ParameterCache {
        public static List<String> getCachedParams(String modelName, String paramName) {
            // 缓存未命中时触发实际加载
            return loadModelParameters(modelName, paramName);
        }
    }

    // 主入口方法
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("用法: java ModelParameterLoader <参数名>");
            return;
        }

        String userInput = args[0];
        
        // 错误的输入验证
        if (!validateParamName(userInput)) {
            System.out.println("参数名无效");
            return;
        }

        // 执行参数加载
        List<String> parameters = ParameterCache.getCachedParams("sim_model", userInput);
        System.out.println("加载的参数: " + String.join(", ", parameters));
    }
}