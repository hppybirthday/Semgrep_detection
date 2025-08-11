import java.sql.*;
import java.util.*;
import spark.*;
import static spark.Spark.*;

public class IoTDeviceServer {
    static Connection conn;

    public static void main(String[] args) throws Exception {
        Class.forName("org.sqlite.JDBC");
        conn = DriverManager.getConnection("jdbc:sqlite:iot.db");
        initializeDatabase();

        port(8080);
        
        post("/register", (req, res) -> {
            String deviceId = req.queryParams("id");
            String type = req.queryParams("type");
            String location = req.queryParams("location");
            
            // Vulnerable SQL statement
            String sql = "INSERT INTO devices(id, type, location) VALUES('" 
                     + deviceId + "', '" + type + "', '" + location + "')";
            conn.createStatement().execute(sql);
            return "Device registered";
        });

        get("/data", (req, res) -> {
            String deviceId = req.queryParams("id");
            StringBuilder result = new StringBuilder();
            
            // Vulnerable SQL query
            ResultSet rs = conn.createStatement()
                .executeQuery("SELECT * FROM sensor_data WHERE device_id='" + deviceId + "'");
            
            while (rs.next()) {
                result.append(String.format("{time: %d, temp: %.1f, humidity: %.1f}\
",
                    rs.getLong(2), rs.getDouble(3), rs.getDouble(4)));
            }
            return result.toString();
        });

        post("/update", (req, res) -> {
            String deviceId = req.queryParams("id");
            String newLocation = req.queryParams("location");
            
            // Vulnerable SQL update
            conn.createStatement().execute(
                "UPDATE devices SET location='" + newLocation + "' WHERE id='" + deviceId + "'"
            );
            return "Location updated";
        });
        
        return "Server started";
    }

    private static void initializeDatabase() throws Exception {
        conn.createStatement().execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                type TEXT,
                location TEXT
            )
        """);

        conn.createStatement().execute("""
            CREATE TABLE IF NOT EXISTS sensor_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                timestamp INTEGER,
                temperature REAL,
                humidity REAL
            )
        """);
    }
}