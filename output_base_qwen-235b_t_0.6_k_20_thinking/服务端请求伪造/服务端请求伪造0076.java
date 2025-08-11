import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class CRMDataImporter {
    private static final String INTERNAL_API_BASE = "http://internal.crm.service/api/v1";
    private static Map<String, String> credentialsStore = new HashMap<>();

    static {
        // 模拟存储敏感凭证
        credentialsStore.put("db_credentials", "admin:securePass123@db.crm.local");
        credentialsStore.put("metadata_token", "AWS4-TOKEN-FOR-INTERNAL-SERVICE");
    }

    public String fetchExternalData(String userProvidedUrl) {
        try {
            // 漏洞点：直接使用用户输入构造URL
            URL url = new URL(userProvidedUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            // 模拟携带内部凭证（攻击利用的关键）
            if (userProvidedUrl.contains("internal.crm.service")) {
                connection.setRequestProperty("Authorization", "Bearer " + credentialsStore.get("metadata_token"));
            }

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            return response.toString();
        } catch (Exception e) {
            return "Error fetching data: " + e.getMessage();
        }
    }

    // 模拟的管理接口（攻击目标）
    public String adminExportEndpoint(String secretToken) {
        if ("ADMIN_SECRET_123".equals(secretToken)) {
            return "Full DB Dump: [" + credentialsStore.toString() + "]";
        }
        return "Unauthorized";
    }

    public static void main(String[] args) {
        CRMDataImporter importer = new CRMDataImporter();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== CRM Data Importer Prototype ===");
        System.out.println("Enter URL to import data (e.g., https://example.com/data): ");
        
        String userInput = scanner.nextLine();
        String result = importer.fetchExternalData(userInput);
        
        System.out.println("\
Response:");
        System.out.println(result);
        scanner.close();
    }
}