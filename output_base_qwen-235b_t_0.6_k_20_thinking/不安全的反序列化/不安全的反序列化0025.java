import java.io.*;
import java.lang.reflect.*;
import java.util.*;

public class BigDataProcessor {
    public static void main(String[] args) {
        try {
            String[] files = {"data1.ser", "data2.ser", "data3.ser"};
            for (String file : files) {
                processSerializedFile(file);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void processSerializedFile(String filename) throws Exception {
        Class<?> handlerClass = Class.forName("com.example.DataHandler");
        Object handlerInstance = handlerClass.getDeclaredConstructor().newInstance();

        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            Object data = ois.readObject(); // 不安全的反序列化漏洞点

            Method processMethod = handlerClass.getMethod("handle", Object.class);
            processMethod.invoke(handlerInstance, data);
        }
    }
}

class DataHandler {
    public void handle(Object obj) {
        System.out.println("Handling data: " + obj.toString());
    }
}

class MaliciousObject implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec("calc"); // 恶意代码执行
    }
}