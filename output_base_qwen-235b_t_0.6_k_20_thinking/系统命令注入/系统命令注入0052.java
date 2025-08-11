import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
public class CommandInjectionDemo {
    public static void main(String[] args) {
        SpringApplication.run(CommandInjectionDemo.class, args);
    }

    public static RouterFunction<ServerResponse> routes() {
        return route(GET("/ping"), request -> {
            String ip = request.queryParam("ip").orElse("127.0.0.1");
            String result = executeCommand("ping -c 4 " + ip);
            return ServerResponse.ok().contentType(MediaType.TEXT_HTML)
                .bodyValue("<html><body><pre>" + result + "</pre></body></html>");
        });
    }

    private static String executeCommand(String command) {
        StringBuilder output = new StringBuilder();
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
        } catch (IOException e) {
            output.append("Execution error: ").append(e.getMessage());
        }
        return output.toString();
    }
}
// Vulnerable when user provides ip="; rm -rf / ;" leading to command injection