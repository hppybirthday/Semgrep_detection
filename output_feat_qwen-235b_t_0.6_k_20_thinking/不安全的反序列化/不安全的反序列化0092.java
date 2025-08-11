import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;

class UserPreferences implements Serializable {
    private static final long serialVersionUID = 1L;
    private String theme;
    private transient Map<String, Object> plugins = new HashMap<>();

    public UserPreferences(String theme) {
        this.theme = theme;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟插件加载逻辑
        plugins.put("themeLoader", (Runnable) () -> {
            try {
                // 危险操作：执行外部命令
                Runtime.getRuntime().exec("/bin/sh -c touch /tmp/exploit");
            } catch (Exception e) { e.printStackTrace(); }
        });
    }
}

class XLSReader {
    public static <T> T read(String path, Class<T> clazz) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path))) {
            return (T) ois.readObject();
        }
    }
}

public class CRMImporter {
    public static void importExcel(String filePath) {
        try {
            UserPreferences prefs = XLSReader.read(filePath, UserPreferences.class);
            System.out.println("Loaded preferences: " + prefs.toString());
        } catch (Exception e) {
            System.err.println("Import failed: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        // 模拟攻击者写入恶意序列化数据
        String filePath = "/tmp/object";
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(Proxy.newProxyInstance(
                CRMImporter.class.getClassLoader(),
                new Class<?>[]{Serializable.class},
                (proxy, method, methodArgs) -> {
                    if (method.getName().equals("run")) {
                        Runtime.getRuntime().exec("/bin/sh -c touch /tmp/pwned");
                    }
                    return null;
                }
            ));
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 模拟真实业务流程触发反序列化
        importExcel(filePath);
    }
}