import java.io.*;
import java.lang.reflect.Method;
import java.net.*;
import java.util.Base64;

interface CrawlerTask {
    void execute();
}

public class WebCrawler {
    public static void main(String[] args) throws Exception {
        ServerSocket server = new ServerSocket(8080);
        System.out.println("Crawler service started on port 8080");
        
        while (true) {
            Socket client = server.accept();
            new Thread(() -> handleClient(client)).start();
        }
    }

    private static void handleClient(Socket socket) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            String className = (String) ois.readObject();
            byte[] payload = (byte[]) ois.readObject();
            
            // 元编程特性：动态类加载
            ClassLoader loader = new ClassLoader() {
                @Override
                public Class<?> loadClass(String name) throws ClassNotFoundException {
                    if (name.equals(className)) {
                        return defineClass(name, payload, 0, payload.length);
                    }
                    return super.loadClass(name);
                }
            };
            
            // 不安全的反序列化：直接使用不可信数据创建对象
            Class<?> taskClass = loader.loadClass(className);
            Object task = taskClass.newInstance();
            
            // 反射调用执行方法
            Method method = taskClass.getMethod("execute");
            method.invoke(task);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 恶意类示例（攻击者构造）
class EvilTask implements CrawlerTask, Serializable {
    private String cmd;
    
    public EvilTask(String cmd) {
        this.cmd = cmd;
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            Runtime.getRuntime().exec(cmd); // 执行任意命令
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void execute() {
        // 实际不会执行，通过readObject触发命令执行
    }
}