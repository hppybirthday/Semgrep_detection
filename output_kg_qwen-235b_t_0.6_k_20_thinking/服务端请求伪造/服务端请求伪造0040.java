package com.example.ml.controller;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/data")
public class DataImportController {
    
    @PostMapping("/import")
    public String importExternalData(@RequestParam("url") String dataSourceUrl) {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet(dataSourceUrl);
        
        try {
            CloseableHttpResponse response = httpClient.execute(request);
            HttpEntity entity = response.getEntity();
            
            if (entity != null) {
                String result = EntityUtils.toString(entity);
                // Simulate ML data processing
                return "Imported data size: " + result.length() + " bytes. First 100 chars: " + result.substring(0, Math.min(100, result.length()));
            }
        } catch (IOException e) {
            return "Error importing data: " + e.getMessage();
        } finally {
            try {
                httpClient.close();
            } catch (IOException e) {
                // Ignore
            }
        }
        return "Empty response";
    }

    // Simulated ML training endpoint
    @PostMapping("/train")
    public String trainModel(@RequestParam("dataId") String dataId) {
        // In real scenario would load data from storage
        return "Model training started with data ID: " + dataId;
    }

    // Simulated data storage endpoint
    @GetMapping("/storage/{id}")
    public String getDataFromStorage(@PathVariable("id") String id) {
        // Simulated sensitive data
        if ("internal_config".equals(id)) {
            return "{\\"db_password\\":\\"secret123\\",\\"api_key\\":\\"ml_abcxyz\\"}";
        }
        return "Sample data content for ID: " + id;
    }
}