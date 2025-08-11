import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// 模拟数学建模插件配置加载器
public class PluginLoader {
    private static final String PLUGIN_ROOT = "/var/mathsim/plugins";
    private final Map<String, PluginConfig> pluginCache = new ConcurrentHashMap<>();

    // 模拟插件配置对象
    public static class PluginConfig {
        private final String name;
        private final String content;

        public PluginConfig(String name, String content) {
            this.name = name;
            this.content = content;
        }

        public String getName() { return name; }
        public String getContent() { return content; }
    }

    // 高风险的插件加载方法
    public PluginConfig loadPluginConfig(String bizPath, String pluginId) throws IOException {
        // 路径拼接漏洞点：直接拼接用户输入
        Path pluginDir = Paths.get(PLUGIN_ROOT + File.separator + bizPath);
        
        // 危险的路径验证（看似安全但可绕过）
        if (!Files.isDirectory(pluginDir)) {
            throw new IOException("Invalid plugin directory: " + pluginDir);
        }

        // 构造最终路径
        Path configPath = pluginDir.resolve(pluginId + "_config.json");
        
        // 实际执行路径解析时已可能跳出限制目录
        if (!Files.exists(configPath)) {
            throw new IOException("Config file not found: " + configPath);
        }

        // 读取配置内容（漏洞利用点）
        String content = Files.readString(configPath);
        return new PluginConfig(pluginId, content);
    }

    // 模拟插件管理接口
    public static void main(String[] args) {
        PluginLoader loader = new PluginLoader();
        try {
            // 示例调用：正常调用
            // PluginConfig config = loader.loadPluginConfig("models/linear", "regression");
            
            // 恶意调用示例：读取系统文件
            PluginConfig config = loader.loadPluginConfig("../../etc", "passwd");
            System.out.println("Loaded config: " + config.getContent());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 模拟插件异常类
class PluginException extends Exception {
    public PluginException(String message) {
        super(message);
    }
}