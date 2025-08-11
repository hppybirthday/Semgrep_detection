import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

@SpringBootApplication
@RestController
public class XssApplication {

    public static void main(String[] args) {
        SpringApplication.run(XssApplication.class, args);
    }

    @GetMapping("/logs")
    public String logs(@RequestParam(name = "keyword", required = false) String keyword) {
        if (keyword == null) keyword = "";
        return "<html><body>" +
               "<h1>Search Logs</h1>" +
               "<div>Search Keyword: " + keyword + "</div>" +
               "<form action='/logs' method='get'>" +
               "<input type='text' name='keyword'>" +
               "<input type='submit' value='Search'>" +
               "</form>" +
               "</body></html>";
    }
}