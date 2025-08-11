import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class XssVulnerableApp {

    @Entity
    public static class AdContent {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;
        private String title;
        private String htmlContent; // Vulnerable field

        // Getters and setters
    }

    public interface AdRepository extends JpaRepository<AdContent, Long> {}

    @Service
    public static class AdService {
        private final AdRepository repository;

        public AdService(AdRepository repository) {
            this.repository = repository;
        }

        public void saveAd(String title, String htmlContent) {
            repository.save(new AdContent(title, htmlContent));
        }

        public List<AdContent> getAllAds() {
            return repository.findAll();
        }
    }

    @RestController
    public static class AdController {
        private final AdService service;
        private final TemplateEngine templateEngine;

        public AdController(AdService service, TemplateEngine templateEngine) {
            this.service = service;
            this.templateEngine = templateEngine;
        }

        @GetMapping("/ads")
        public String listAds() {
            Context context = new Context();
            context.setVariable("ads", service.getAllAds());
            return templateEngine.process("ads", context);
        }

        @PostMapping("/crawl")
        public String addAd(@RequestParam String title, @RequestParam String content) {
            // Simulate crawler storing malicious content
            service.saveAd(title, content);
            return "redirect:/ads";
        }
    }

    // Thymeleaf template (resources/templates/ads.html)
    // <div th:each="ad : ${ads}">
    //     <h3 th:text="${ad.title}"></h3>
    //     <div th:utext="${ad.htmlContent}"></div>  // Vulnerable line (utext disables escaping)
    // </div>

    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }
}