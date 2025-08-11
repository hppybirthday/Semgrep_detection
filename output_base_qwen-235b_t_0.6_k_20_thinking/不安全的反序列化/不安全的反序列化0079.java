import java.io.*;
import java.util.HashMap;
import java.util.Map;

// 模拟微服务消息处理器
interface MessageHandler {
    void processMessage(byte[] message);
}

// 核心业务对象
abstract class Order implements Serializable {
    public abstract double calculateTotal();
}

// 具体订单实现
class ShoppingCartOrder extends Order {
    private Map<String, Double> items = new HashMap<>();

    public void addItem(String product, double price) {
        items.put(product, price);
    }

    @Override
    public double calculateTotal() {
        return items.values().stream().mapToDouble(Double::doubleValue).sum();
    }
}

// 漏洞核心：不安全的反序列化处理器
class UnsafeDeserializer implements MessageHandler {
    @Override
    public void processMessage(byte[] message) {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(message))) {
            // 直接反序列化未经验证的输入
            Order order = (Order) ois.readObject();
            System.out.println("Order total: $" + order.calculateTotal());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 模拟消息队列消费者
class QueueConsumer {
    private MessageHandler handler;

    public void setHandler(MessageHandler handler) {
        this.handler = handler;
    }

    public void receiveMessage(byte[] message) {
        System.out.println("[Message received]");
        handler.processMessage(message);
    }
}

// 模拟攻击载荷
class MaliciousPayload implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // 模拟任意代码执行
        Runtime.getRuntime().exec("calc"); // 模拟攻击行为
    }
}

// 微服务启动类
public class OrderServiceApplication {
    public static void main(String[] args) throws IOException {
        QueueConsumer consumer = new QueueConsumer();
        consumer.setHandler(new UnsafeDeserializer());

        // 模拟正常消息
        Order normalOrder = new ShoppingCartOrder();
        ((ShoppingCartOrder) normalOrder).addItem("Book", 29.99);
        
        // 序列化正常消息
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(normalOrder);
        byte[] normalMessage = bos.toByteArray();
        
        // 模拟攻击消息
        bos = new ByteArrayOutputStream();
        oos = new ObjectOutputStream(bos);
        oos.writeObject(new MaliciousPayload()); // 植入恶意对象
        byte[] attackMessage = bos.toByteArray();
        
        // 正常处理
        System.out.println("Processing normal message:");
        consumer.receiveMessage(normalMessage);
        
        // 攻击演示（实际攻击通过网络传输）
        System.out.println("\
Injecting malicious message:");
        consumer.receiveMessage(attackMessage);
    }
}