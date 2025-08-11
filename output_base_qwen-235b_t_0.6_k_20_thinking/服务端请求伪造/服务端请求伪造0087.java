import java.io.*;
import java.net.*;
import java.util.*;

// 领域模型
class User {
    private String username;
    private String avatarUrl;

    public User(String username, String avatarUrl) {
        this.username = username;
        this.avatarUrl = avatarUrl;
    }

    public String getUsername() { return username; }
    public String getAvatarUrl() { return avatarUrl; }
}

// 服务层
class AvatarService {
    public byte[] fetchAvatar(String avatarUrl) throws IOException {
        URL url = new URL(avatarUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        // 模拟处理响应
        if (connection.getResponseCode() == 200) {
            InputStream is = connection.getInputStream();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[1024];
            while ((nRead = is.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            return buffer.toByteArray();
        }
        return new byte[0];
    }
}

// 应用服务
class GameProfileService {
    private AvatarService avatarService = new AvatarService();

    public void updateProfile(User user) {
        try {
            byte[] avatarData = avatarService.fetchAvatar(user.getAvatarUrl());
            System.out.println("[+] Avatar for " + user.getUsername() + " fetched successfully (" + avatarData.length + " bytes)");
            // 实际应保存到存储系统
        } catch (Exception e) {
            System.err.println("[-] Failed to fetch avatar: " + e.getMessage());
        }
    }
}

// 主程序
public class GameServer {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        System.out.print("Enter avatar URL: ");
        String avatarUrl = scanner.nextLine();
        
        User user = new User(username, avatarUrl);
        new GameProfileService().updateProfile(user);
    }
}