import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;

// 模拟IoT设备接收控制命令
class TemperatureCommand implements Serializable {
    private static final long serialVersionUID = 1L;
    private double targetTemp;
    private String executeTime;
    
    public TemperatureCommand(double temp, String time) {
        this.targetTemp = temp;
        this.executeTime = time;
    }
    
    public void execute() {
        System.out.println("Setting temperature to " + targetTemp + " at " + executeTime);
    }
}

// 不安全的命令处理器
class CommandProcessor {
    public void processCommand(byte[] data) {
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject();
            if (obj instanceof TemperatureCommand) {
                ((TemperatureCommand) obj).execute();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 模拟IoT服务器接收设备数据
public class IoTServer {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            System.out.println("IoT Server started on port 8080");
            
            while (true) {
                Socket socket = serverSocket.accept();
                InputStream input = socket.getInputStream();
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                
                int data;
                while ((data = input.read()) != -1) {
                    buffer.write(data);
                }
                
                byte[] receivedData = buffer.toByteArray();
                System.out.println("Received data: " + Base64.getEncoder().encodeToString(receivedData));
                
                new CommandProcessor().processCommand(receivedData);
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // 模拟生成恶意payload的方法
    public static byte[] createMaliciousPayload() {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = bos;
            // 实际攻击中会构造包含恶意代码的序列化对象
            // 这里为示例使用合法对象
            oos.writeObject(new TemperatureCommand(100.0, "now"));
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}