import java.io.*;
import java.net.*;
import java.util.*;

class GameResourceLoader {
    private static final String BASE_URL = "https://game-resources.example.com/";
    
    public byte[] loadCustomAsset(String userProvidedPath) throws IOException {
        URL fullUrl;
        if (userProvidedPath.startsWith("http")) {
            fullUrl = new URL(userProvidedPath);
        } else {
            fullUrl = new URL(BASE_URL + userProvidedPath);
        }
        
        HttpURLConnection connection = (HttpURLConnection) fullUrl.openConnection();
        connection.setRequestMethod("GET");
        
        if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
            InputStream input = connection.getInputStream();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
            return output.toByteArray();
        }
        return null;
    }
}

class PlayerProfile {
    private String name;
    private byte[] avatarImage;
    private GameResourceLoader resourceLoader;

    public PlayerProfile(String name, String avatarUrl) throws IOException {
        this.name = name;
        this.resourceLoader = new GameResourceLoader();
        this.avatarImage = loadAvatar(avatarUrl);
    }

    private byte[] loadAvatar(String avatarUrl) throws IOException {
        // 漏洞触发点：直接使用用户输入的URL
        return resourceLoader.loadCustomAsset(avatarUrl);
    }

    public void displayProfile() {
        System.out.println("Player: " + name);
        System.out.println("Avatar size: " + (avatarImage != null ? avatarImage.length : 0) + " bytes");
    }
}

public class GameServer {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter player name:");
        String name = scanner.nextLine();
        
        System.out.println("Enter avatar URL (can be external or internal path):);
        String avatarUrl = scanner.nextLine();
        
        try {
            PlayerProfile profile = new PlayerProfile(name, avatarUrl);
            profile.displayProfile();
        } catch (IOException e) {
            System.err.println("Failed to load profile: " + e.getMessage());
        }
    }
}