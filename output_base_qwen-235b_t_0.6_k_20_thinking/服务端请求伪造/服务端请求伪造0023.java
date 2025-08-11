import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

class HttpClient {
    public String sendGetRequest(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        return response.toString();
    }
}

class GameServer {
    private HttpClient httpClient = new HttpClient();
    private String serverAddress;

    public GameServer(String serverAddress) {
        this.serverAddress = serverAddress;
    }

    public String handleRequest(String playerName) {
        try {
            // 漏洞点：直接拼接用户输入到URL中
            String url = "http://" + serverAddress + "/api/players?name=" + playerName;
            return httpClient.sendGetRequest(url);
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
}

class Player {
    private String name;
    private GameServer gameServer;

    public Player(String name, String serverAddress) {
        this.name = name;
        this.gameServer = new GameServer(serverAddress);
    }

    public String fetchPlayerData() {
        return gameServer.handleRequest(this.name);
    }
}

public class Main {
    public static void main(String[] args) {
        // 模拟用户输入
        String playerName = "testPlayer";
        String serverAddress = "example.com"; // 正常情况
        
        // 攻击示例：通过serverAddress参数发起SSRF攻击
        Player attacker = new Player(playerName, "localhost:8080/admin");
        System.out.println("[Attack Result] " + attacker.fetchPlayerData());
        
        // 正常用户示例
        Player normalPlayer = new Player(playerName, serverAddress);
        System.out.println("[Normal Result] " + normalPlayer.fetchPlayerData());
    }
}