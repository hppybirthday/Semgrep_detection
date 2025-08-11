package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssBigDataApp {
    public static void main(String[] args) {
        SpringApplication.run(XssBigDataApp.class, args);
    }
}

@RestController
@RequestMapping("/search")
class SearchController {
    private final SearchService searchService = new SearchService();

    @GetMapping
    public String handleSearch(@RequestParam String query) {
        return searchService.generateSearchResults(query);
    }
}

@Service
class SearchService {
    public String generateSearchResults(String query) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>");
        html.append("<html><head><title>Search Results</title>");
        html.append("<script>function loadChart(){/* BigData Visualization */}</script>");
        html.append("</head><body>");
        html.append("<h1>Results for: ").append(query).append("</h1>"); // Vulnerable point
        html.append("<div id='results'>");
        
        // Simulated big data processing results
        List<String> mockResults = getMockSearchResults(query);
        for (String result : mockResults) {
            html.append("<div class='result-item'>").append(result).append("</div>");
        }
        
        html.append("</div>");
        html.append("<div id='analytics'>");
        html.append("<canvas id='dataChart' onload='loadChart()'></canvas>");
        html.append("</div>");
        html.append("</body></html>");
        return html.toString();
    }

    private List<String> getMockSearchResults(String query) {
        List<String> results = new ArrayList<>();
        results.add("DataPoint: " + query + " - Volume: 1.2TB");
        results.add("Node: " + query + " - Status: Active");
        results.add("Last processed: " + System.currentTimeMillis());
        return results;
    }
}
