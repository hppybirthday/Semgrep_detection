import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@SpringBootApplication
public class CrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrawlerApplication.class, args);
    }
}

@RestController
@RequestMapping("/api")
class CrawlerController {
    private String dataSourceUri = "http://default.example.com";

    @GetMapping("/form")
    public String getForm() {
        return "<form method='post' action='/api/config'>"
               + "URI: <input type='text' name='uri'>"
               + "<input type='submit' value='Submit'>"
               + "</form>";
    }

    @PostMapping("/config")
    public ResponseEntity<String> postDataSource(@RequestParam String uri) throws IOException {
        this.dataSourceUri = uri;
        URL url = new URL(uri);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        int responseCode = connection.getResponseCode();
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();

        String result = "Data source updated to: " + uri + "<br>Response Code: " + responseCode + "<br>Content: " + response.toString();
        return ResponseEntity.ok(result);
    }

    @GetMapping("/internal")
    public String internalEndpoint() {
        return "Internal endpoint. Data source URI: " + dataSourceUri;
    }
}