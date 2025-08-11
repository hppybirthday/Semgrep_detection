import java.io.*;
import java.util.ArrayList;
import java.util.List;

// 用户数据类
class User implements Serializable {
    private String username;
    private String password;
    private List<String> permissions;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
        this.permissions = new ArrayList<>();
    }

    public String getUsername() { return username; }
    public List<String> getPermissions() { return permissions; }

    // 模拟数据处理逻辑
    public void processData() {
        System.out.println("Processing data for user: " + username);
    }
}

// 大数据处理模块
class DataProcessor {
    // 不安全的反序列化操作
    public User loadUser(String filePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // 危险的反序列化操作
            return (User) ois.readObject();
        }
    }

    public void analyzeData(String filePath) throws IOException, ClassNotFoundException {
        User user = loadUser(filePath);
        System.out.println("Analyzing data for: " + user.getUsername());
        user.processData();
    }
}

// 恶意攻击演示类
class MaliciousCode {
    // 实际攻击中可能包含任意恶意代码
    private void execCommand() {
        try {
            Runtime.getRuntime().exec("calc"); // 示例攻击命令
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 主程序入口
public class BigDataSystem {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java BigDataSystem <file_path>");
            return;
        }

        try {
            DataProcessor processor = new DataProcessor();
            processor.analyzeData(args[0]);
        } catch (Exception e) {
            System.err.println("Error processing file: " + e.getMessage());
        }
    }
}