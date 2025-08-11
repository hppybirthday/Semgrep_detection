import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

public class FileCryptoService {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String SECRET_KEY = "1234567890123456";

    public static void main(String[] args) {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);

        // Vulnerable file download endpoint
        router.get("/download").handler(handleDownload());
        // File encryption endpoint
        router.post("/encrypt").handler(handleEncryption());

        vertx.createHttpServer().requestHandler(router).listen(8080);
        System.out.println("Server started on port 8080");
    }

    private static Function<RoutingContext, Void> handleDownload() {
        return ctx -> {
            try {
                String fileUrl = ctx.request().getParam("url"); // User-controlled URL
                HttpClient client = HttpClient.newHttpClient();
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(fileUrl)) // SSRF vulnerability here
                    .build();
                
                // Directly download from user-specified URL
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                ctx.response().putHeader("Content-Type", "application/octet-stream")
                    .putHeader("Content-Disposition", "attachment; filename=downloaded_file.enc")
                    .end(encrypt(response.body()));
            } catch (Exception e) {
                ctx.fail(500, e);
            }
            return null;
        };
    }

    private static Function<RoutingContext, Void> handleEncryption() {
        return ctx -> {
            try {
                String fileName = ctx.request().getParam("file");
                byte[] fileContent = Files.readAllBytes(Paths.get("uploads/", fileName));
                String encrypted = encrypt(new String(fileContent));
                ctx.response().end(encrypted);
            } catch (Exception e) {
                ctx.fail(500, e);
            }
            return null;
        };
    }

    private static String encrypt(String value) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(value.getBytes()));
    }
}