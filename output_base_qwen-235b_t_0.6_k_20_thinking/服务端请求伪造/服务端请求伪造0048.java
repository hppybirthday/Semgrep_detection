import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import com.sun.net.httpserver.*;

public class FileEncryptor {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/encrypt", exchange -> {
            String url = exchange.getRequestURI().getQuery();
            url = url.replace("url=", "");
            
            try {
                URL obj = new URL(url);
                HttpURLConnection con = (HttpURLConnection) obj.openConnection();
                con.setRequestMethod("GET");
                
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(con.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();
                
                while ((inputLine = in.readLine()) != null) {
                    content.append(inputLine);
                }
                in.close();
                con.disconnect();
                
                String encrypted = encrypt(content.toString());
                exchange.sendResponseHeaders(200, encrypted.length());
                OutputStream os = exchange.getResponseBody();
                os.write(encrypted.getBytes());
                os.close();
                
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
                exchange.getResponseBody().close();
            }
        });
        server.setExecutor(null);
        server.start();
    }

    private static String encrypt(String data) throws Exception {
        String key = "1234567890123456";
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
}