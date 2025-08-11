import java.io.*;
import java.net.*;
import java.util.Base64;

/**
 * 模拟IoT设备控制中心，接收序列化数据包执行设备配置
 */
public class IoTDeviceController {
    
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(8080);
            System.out.println("IoT控制中心已启动");
            
            while(true) {
                Socket socket = serverSocket.accept();
                handleClient(socket);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void handleClient(Socket socket) {
        try {
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            DeviceConfig config = (DeviceConfig) ois.readObject();
            
            // 模拟应用配置
            System.out.println("应用设备配置: " + config.getDeviceId());
            System.out.println("执行操作: " + config.getOperation());
            
            // 危险操作：执行系统命令
            if("reboot".equals(config.getOperation())) {
                Runtime.getRuntime().exec("/sbin/reboot");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/**
 * 可序列化的设备配置类
 */
class DeviceConfig implements Serializable {
    private String deviceId;
    private String operation;
    
    public DeviceConfig(String deviceId, String operation) {
        this.deviceId = deviceId;
        this.operation = operation;
    }
    
    public String getDeviceId() {
        return deviceId;
    }
    
    public String getOperation() {
        return operation;
    }
}

/**
 * 攻击者示例代码（实际攻击不会包含在此）
 */
class MaliciousPayload implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // 模拟执行任意代码
        Runtime.getRuntime().exec("calc");
    }
}