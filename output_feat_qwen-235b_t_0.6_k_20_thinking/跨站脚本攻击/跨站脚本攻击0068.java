import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@SpringBootApplication
public class App {
    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}

@Controller
class SearchController {
    @GetMapping("/")
    String search(@RequestParam(name="keyword", required=false) String keyword, Map<String, Object> model) {
        model.put("keyword", keyword != null ? keyword : "");
        return "search";
    }
}