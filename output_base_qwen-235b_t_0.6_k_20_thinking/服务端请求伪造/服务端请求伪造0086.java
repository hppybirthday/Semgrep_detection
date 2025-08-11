import static spark.Spark.*;
import java.io.*;
import java.net.*;
import java.util.*;
import com.google.gson.*;

public class IoTDeviceProxy {
    private static final Gson gson = new Gson();
    
    public static void main(String[] args) {
        port(8080);
        
        get("/device/data", (req, res) -> {
            String deviceUrl = req.queryParams("deviceUrl");
            if (deviceUrl == null || deviceUrl.isEmpty()) {
                res.status(400);
                return gson.toJson(Map.of("error", "Missing device URL"));
            }
            
            try {
                URL url = new URL(deviceUrl);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                
                int responseCode = conn.getResponseCode();
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
                String inputLine;
                StringBuilder response = new StringBuilder();
                
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
                
                return gson.toJson(Map.of(
                    "status", responseCode,
                    "data", response.toString()
                ));
                
            } catch (Exception e) {
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });
        
        // 管理接口（本应受保护）
        get("/admin/config", (req, res) -> {
            res.type("application/json");
            return gson.toJson(Map.of(
                "secretKey", "IoT_ADMIN_TOKEN_2023",
                "internalDbUrl", "jdbc:mysql://localhost:3306/iot_data"
            ));
        });
    }
}