import java.io.*;
import java.util.Base64;

// 用户信息类（包含敏感数据）
class User implements Serializable {
    private String username;
    private String password;
    private boolean isAdmin;

    public User(String username, String password, boolean isAdmin) {
        this.username = username;
        this.password = password;
        this.isAdmin = isAdmin;
    }

    // 模拟敏感操作
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (isAdmin) {
            System.out.println("[危险操作] 管理员权限验证通过");
        }
    }
}

// 数据存储管理类
class DataStorage {
    // 模拟从本地存储读取数据（可能被篡改）
    public static Object loadUserData(String filePath) throws IOException, ClassNotFoundException {
        File file = new File(filePath);
        if (!file.exists()) {
            System.out.println("未找到数据文件");
            return null;
        }

        try (FileInputStream fis = new FileInputStream(file);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            
            // 防御式编程：尝试验证类类型（看似安全但存在绕过可能）
            Object obj = ois.readObject();
            if (obj.getClass().getName().equals("User")) {
                return obj;
            } else {
                System.out.println("检测到非法类类型: " + obj.getClass().getName());
                return null;
            }
        }
    }

    // 模拟保存数据到本地
    public static void saveUserData(String filePath, Object data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(data);
        }
    }
}

// 模拟攻击者构造的恶意类
class MaliciousUser implements Serializable {
    private String command;

    public MaliciousUser(String command) {
        this.command = command;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟执行任意命令
        Runtime.getRuntime().exec(command);
    }
}

// 移动应用主类
public class MobileApp {
    public static void main(String[] args) {
        String dataPath = "userdata.ser";

        try {
            // 模拟首次运行保存用户数据
            System.out.println("首次保存用户数据...");
            DataStorage.saveUserData(dataPath, new User("test", "pass123", false));
            
            // 模拟应用重启时加载数据
            System.out.println("加载用户数据...");
            Object userData = DataStorage.loadUserData(dataPath);
            
            // 模拟攻击者替换数据文件
            System.out.println("\
[攻击模拟] 篡改数据文件...");
            DataStorage.saveUserData(dataPath, new MaliciousUser("notepad"));
            
            // 再次加载被篡改的数据
            System.out.println("加载被篡改的数据...");
            DataStorage.loadUserData(dataPath);
            
        } catch (Exception e) {
            System.out.println("操作失败: " + e.getMessage());
        }
    }
}