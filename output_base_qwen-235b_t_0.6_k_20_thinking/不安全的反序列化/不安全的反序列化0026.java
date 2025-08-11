import java.io.*;
import java.util.*;

// 模拟数据清洗的上下文类
class CleaningContext implements Serializable {
    private Map<String, Object> data = new HashMap<>();

    public void addData(String key, Object value) {
        data.put(key, value);
    }

    public Object getData(String key) {
        return data.get(key);
    }
}

// 可能被污染的数据对象
class UserRecord implements Serializable {
    private String username;
    private transient String sensitiveData; // 敏感字段

    public UserRecord(String username) {
        this.username = username;
        this.sensitiveData = "DEFAULT_SECRET";
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟数据清洗时的错误逻辑
        if (sensitiveData == null || sensitiveData.isEmpty()) {
            sensitiveData = "RECOVERED_SECRET";
        }
    }

    @Override
    public String toString() {
        return "UserRecord{username='" + username + "', sensitiveData='" + sensitiveData + "'}";
    }
}

// 不安全的数据清洗器
class DataCleaner {
    public static CleaningContext unsafeDeserialize(byte[] data) {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            // 不安全的反序列化操作
            return (CleaningContext) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        // 模拟正常数据清洗流程
        CleaningContext context = new CleaningContext();
        context.addData("user1", new UserRecord("admin"));
        
        // 模拟序列化传输
        byte[] serializedData;
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(context);
            serializedData = bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        
        // 模拟反序列化清洗
        CleaningContext recovered = unsafeDeserialize(serializedData);
        System.out.println("Recovered data: " + recovered.getData("user1"));
    }
}

// 恶意类示例（模拟攻击者构造的payload）
class MaliciousPayload implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // 模拟执行任意代码（实际攻击中可能更隐蔽）
        Runtime.getRuntime().exec("calc"); // 示例：打开计算器
    }
}