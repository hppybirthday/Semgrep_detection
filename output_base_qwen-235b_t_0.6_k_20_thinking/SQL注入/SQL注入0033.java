import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;

public class WebCrawler {
    private String dbUrl = "jdbc:mysql://localhost:3306/crawler_db";
    private String dbUser = "root";
    private String dbPassword = "password";

    public static void main(String[] args) {
        WebCrawler crawler = new WebCrawler();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter URL to crawl: ");
        String url = scanner.nextLine();
        crawler.crawl(url);
    }

    public void crawl(String targetUrl) {
        try {
            URL url = new URL(targetUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            if (connection.getResponseCode() == 200) {
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()));
                StringBuilder content = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line);
                }
                reader.close();
                
                // Extract title as demo data
                String title = extractTitle(content.toString());
                String pageContent = content.substring(0, Math.min(200, content.length()));
                
                DataStorage storage = new DataStorage(dbUrl, dbUser, dbPassword);
                storage.saveData(title, pageContent);
                System.out.println("Data saved successfully");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String extractTitle(String html) {
        int start = html.indexOf("<title>") + 7;
        int end = html.indexOf("</title>");
        return (start > 6 && end > start) ? html.substring(start, end) : "No Title";
    }
}

class DataStorage {
    private String dbUrl;
    private String dbUser;
    private String dbPassword;

    public DataStorage(String dbUrl, String dbUser, String dbPassword) {
        this.dbUrl = dbUrl;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
    }

    public void saveData(String title, String content) throws SQLException {
        Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
        Statement stmt = conn.createStatement();
        // Vulnerable SQL injection point
        String sql = "INSERT INTO data (title, content) VALUES ('" + title + "', '" + content + "')";
        stmt.executeUpdate(sql);
        stmt.close();
        conn.close();
    }
}

class DBUtil {
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}