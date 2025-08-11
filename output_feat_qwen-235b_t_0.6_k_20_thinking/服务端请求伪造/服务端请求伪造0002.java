import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.*;
import reactor.core.publisher.Mono;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.function.Function;

@SpringBootApplication
public class ChatApp {
    public static void main(String[] args) {
        SpringApplication.run(ChatApp.class, args);
    }

    public static RouterFunction<ServerResponse> routes() {
        return RouterFunctions.route()
            .POST("/attachments/upload-from-url", ChatApp::handleUploadFromUrl)
            .build();
    }

    private static Mono<ServerResponse> handleUploadFromUrl(ServerRequest request) {
        return request.formData().map(data -> {
            String picUrl = data.getFirst("picUrl");
            if (picUrl == null || picUrl.isEmpty()) {
                return ServerResponse.badRequest().bodyValue("Missing picUrl");
            }
            
            try {
                // Vulnerable code: Directly using user input to construct request
                HttpClient client = HttpClient.newHttpClient();
                HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(picUrl))
                    .GET()
                    .build();

                HttpResponse<byte[]> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
                
                if (response.statusCode() == 200) {
                    byte[] imageData = response.body();
                    String base64Image = Base64.getEncoder().encodeToString(imageData);
                    return ServerResponse.ok().bodyValue("{\\"url\\":\\"data:image/jpeg;base64," + base64Image + "\\"}");
                }
                return ServerResponse.status(500).bodyValue("Failed to fetch image");
            } catch (Exception e) {
                return ServerResponse.status(500).bodyValue("{\\"error\\":\\"" + e.getMessage() + "\\"}");
            }
        }).flatMap(Function.identity());
    }
}