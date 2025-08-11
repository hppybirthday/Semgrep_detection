package com.example.bigdata.report;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/report")
public class ReportController {
    @Autowired
    private ReportService reportService;

    @GetMapping("/generate")
    public String generateReport(@RequestParam String queryTerm) {
        return reportService.generateHtmlReport(queryTerm);
    }
}

@Service
class ReportService {
    private final DataRepository dataRepository;

    public ReportService(DataRepository dataRepository) {
        this.dataRepository = dataRepository;
    }

    public String generateHtmlReport(String queryTerm) {
        List<String> results = dataRepository.searchData(queryTerm);
        
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>Search Report for: ").append(queryTerm).append("</h1>"); // Vulnerable point
        html.append("<ul>");
        for (String result : results) {
            html.append("<li>").append(result).append("</li>");
        }
        html.append("</ul>");
        html.append("<script>console.log('Report generated at: ").append(System.currentTimeMillis()).append("')</script>");
        html.append("</body></html>");
        return html.toString();
    }
}

interface DataRepository {
    List<String> searchData(String query);
}

// Fake implementation for demonstration
class DatabaseSimulator implements DataRepository {
    @Override
    public List<String> searchData(String query) {
        // Simulate database search with hardcoded results
        return List.of("DataPoint1", "DataPoint2", "RelevantResultFor: " + query);
    }
}

// Domain model
record ReportMetadata(String title, String description) {}

// Configuration class (simplified)
@Configuration
class ReportConfig {
    @Bean
    DataRepository dataRepository() {
        return new DatabaseSimulator();
    }

    @Bean
    ReportService reportService() {
        return new ReportService(dataRepository());
    }
}