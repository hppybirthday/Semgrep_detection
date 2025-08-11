import spark.Request;
import spark.Response;
import spark.Route;
import spark.Spark;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.Base64;

public class FileCryptoService {
    
    // 模拟加密函数
    static String encrypt(byte[] data) {
        return Base64.getEncoder().encodeToString(data); // 实际应使用安全加密算法
    }
    
    // 模拟解密函数
    static byte[] decrypt(String encryptedData) {
        return Base64.getDecoder().decode(encryptedData);
    }

    public static void main(String[] args) {
        Spark.port(8080);
        
        // 文件加密接口
        Spark.post("/encrypt", (req, res) -> {
            String fileUrl = req.queryParams("fileUrl");
            if (fileUrl == null || fileUrl.isEmpty()) {
                res.status(400);
                return "Missing fileUrl parameter";
            }
            
            try {
                // SSRF漏洞点：直接使用用户输入构造URL请求
                URL url = new URL(fileUrl);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                
                // 读取远程文件内容
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int len;
                try (InputStream is = conn.getInputStream()) {
                    while ((len = is.read(buffer)) > -1) {
                        baos.write(buffer, 0, len);
                    }
                }
                
                // 执行加密操作
                String encrypted = encrypt(baos.toByteArray());
                res.type("application/json");
                return String.format("{\\"encrypted_data\\":\\"%s\\"}", encrypted);
                
            } catch (Exception e) {
                res.status(500);
                return "Error processing file: " + e.getMessage();
            }
        });
        
        // 文件解密接口
        Spark.post("/decrypt", (req, res) -> {
            String encryptedData = req.body();
            if (encryptedData == null || encryptedData.isEmpty()) {
                res.status(400);
                return "Missing encrypted data";
            }
            
            try {
                // 执行解密操作
                byte[] decrypted = decrypt(encryptedData);
                res.type("application/octet-stream");
                return decrypted;
                
            } catch (Exception e) {
                res.status(500);
                return "Decryption error: " + e.getMessage();
            }
        });
    }
}