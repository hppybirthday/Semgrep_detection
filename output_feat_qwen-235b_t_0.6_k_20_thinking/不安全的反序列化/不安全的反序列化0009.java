import java.io.*;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

// 抽象数据处理接口
interface DataProcessor {
    void process(Object data);
}

// MapReduce任务配置类
abstract class TaskConfig implements Serializable {
    abstract void execute();
}

// 具体实现类
class MaliciousTask extends TaskConfig {
    private String cmd;
    public MaliciousTask(String cmd) { this.cmd = cmd; }
    public void execute() {
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 数据序列化工具类
class DataSerializer {
    static byte[] serialize(Object obj) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.flush();
        return bos.toByteArray();
    }
}

// 反序列化服务类
class DeserializationService {
    static Object unsafeDeserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new AntObjectInputStream(new ByteArrayInputStream(data)); // 不安全的反序列化入口
        return ois.readObject();
    }
}

// HTTP请求处理类
class RequestHandler {
    private DataProcessor processor;
    
    // 模拟处理大数据更新请求
    void updateDepotItem(String objParam) {
        try {
            // 直接反序列化HTTP参数内容
            byte[] serializedData = Base64.getDecoder().decode(objParam);
            Object obj = DeserializationService.unsafeDeserialize(serializedData);
            
            if (obj instanceof DataProcessor) {
                processor = (DataProcessor) obj;
                processor.process(new Date()); // 触发执行
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 自定义ObjectInputStream
class AntObjectInputStream extends ObjectInputStream {
    AntObjectInputStream(InputStream in) throws IOException {
        super(in);
    }
}

// 模拟入口类
public class VulnerableBigDataApp {
    public static void main(String[] args) throws Exception {
        // 模拟攻击载荷构造
        TaskConfig payload = new MaliciousTask("calc"); // 恶意执行命令
        byte[] maliciousData = DataSerializer.serialize(payload);
        
        // 模拟HTTP请求触发
        RequestHandler handler = new RequestHandler();
        handler.updateDepotItem(Base64.getEncoder().encodeToString(maliciousData)); // 触发漏洞
    }
}