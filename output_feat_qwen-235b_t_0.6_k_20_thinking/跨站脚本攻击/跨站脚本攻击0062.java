import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class XssApp {
    public static void main(String[] args) {
        SpringApplication.run(XssApp.class, args);
    }

    @Bean
    public RouterFunction<ServerResponse> routes() {
        return route(GET("/profile"), request -> {
            String name = request.queryParam("name").orElse("Guest");
            Map<String, Object> model = new HashMap<>();
            model.put("name", name);
            return ServerResponse.ok().render("profile", model);
        });
    }
}

// Thymeleaf template (resources/templates/profile.html)
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <div>
//         <h1 th:text="${name}">Welcome Guest</h1> <!-- Vulnerable line -->
//         <p th:utext="${'<script>alert(1)</script>' + name}"></p> <!-- Double vulnerability -->
//     </div>
// </body>
// </html>

// application.properties配置
// spring.thymeleaf.prefix=classpath:/templates/
// spring.thymeleaf.suffix=.html
// spring.thymeleaf.mode=HTML
// spring.thymeleaf.cache=false