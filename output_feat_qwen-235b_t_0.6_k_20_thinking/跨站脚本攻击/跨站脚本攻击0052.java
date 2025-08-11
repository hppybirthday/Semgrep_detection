import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import reactor.core.publisher.Mono;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;

@SpringBootApplication
public class XssVulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }

    @Bean
    public RouterFunction<ServerResponse> searchRoute(SearchHandler handler) {
        return RouterFunctions.route(GET("/search"), handler::handleSearch);
    }
}

@Component
class SearchHandler {
    private final TemplateEngine templateEngine;

    public SearchHandler(TemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    public Mono<ServerResponse> handleSearch(ServerRequest request) {
        String keyword = request.queryParam("keyword").orElse("");
        Context context = new Context();
        context.setVariable("keyword", keyword);
        String html = templateEngine.process("search", context);
        return ServerResponse.ok().contentType(org.springframework.http.MediaType.TEXT_HTML).bodyValue(html);
    }
}
