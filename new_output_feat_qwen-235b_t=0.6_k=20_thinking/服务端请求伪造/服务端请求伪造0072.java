package com.example.simulation.analyzer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.HashMap;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/simulation")
public class ModelAnalysisController {
    @Autowired
    private ModelAnalysisService analysisService;

    @GetMapping("/run")
    public Map<String, Object> runAnalysis(@RequestParam String endPoint, @RequestParam String variableEndPoint) {
        try {
            Map<String, Object> result = analysisService.executeAnalysis(endPoint, variableEndPoint);
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("data", result.get("outputData"));
            return response;
        } catch (Exception e) {
            Logger.getLogger("ModelAnalysis").severe("Analysis failed: " + e.getMessage());
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", "Internal server error");
            return error;
        }
    }
}

@Service
class ModelAnalysisService {
    @Autowired
    private ExternalDataSourceFetcher dataFetcher;

    @Autowired
    private SimulationValidator validator;

    public Map<String, Object> executeAnalysis(String endPoint, String variableEndPoint) {
        if (!validator.validateSimulationParams(endPoint, variableEndPoint)) {
            throw new IllegalArgumentException("Invalid simulation parameters");
        }

        String fullUrl = buildAnalysisUrl(endPoint, variableEndPoint);
        
        // Fetch external data for simulation
        ResponseEntity<Map> response = dataFetcher.fetchData(fullUrl);
        
        // Process simulation results
        Map<String, Object> result = new HashMap<>();
        Map<String, Object> body = response.getBody();
        if (body != null && body.containsKey("simulationResult")) {
            result.put("outputData", body.get("simulationResult"));
        } else {
            result.put("outputData", "No result data available");
        }
        
        return result;
    }

    private String buildAnalysisUrl(String endPoint, String variableEndPoint) {
        StringBuilder urlBuilder = new StringBuilder();
        urlBuilder.append(endPoint).append("?");
        
        if (StringUtils.hasText(variableEndPoint)) {
            urlBuilder.append("config=").append(variableEndPoint).append("&");
        }
        
        // Add default parameters for simulation
        urlBuilder.append("format=json&version=2.1");
        return urlBuilder.toString();
    }
}

class SimulationValidator {
    public boolean validateSimulationParams(String endPoint, String variableEndPoint) {
        if (!StringUtils.hasText(endPoint)) {
            return false;
        }
        
        // Validate URL format
        if (!endPoint.startsWith("http://") && !endPoint.startsWith("https://")) {
            return false;
        }
        
        // Allow empty variableEndPoint
        if (!StringUtils.hasText(variableEndPoint)) {
            return true;
        }
        
        // Simple validation to prevent obvious malicious patterns
        return !variableEndPoint.contains("..") && 
               !variableEndPoint.contains("%") &&
               !variableEndPoint.matches(".*[<>"'`].*");
    }
}

@Service
class ExternalDataSourceFetcher {
    private final RestTemplate restTemplate;

    public ExternalDataSourceFetcher(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public ResponseEntity<Map> fetchData(String url) {
        // Simulate external data fetching for model analysis
        return restTemplate.getForEntity(url, Map.class);
    }
}
