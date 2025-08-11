package com.example.product.controller;

import com.example.product.service.RecommendService;
import com.example.product.dto.RecommendRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/recommend")
public class RecommendController {
    @Autowired
    private RecommendService recommendService;

    @PostMapping("/batch")
    public String batchInsert(@RequestBody RecommendRequest request) {
        try {
            recommendService.processRecommendations(request.getClients(), request.getProductIds());
            return "Success";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

package com.example.product.service;

import com.example.product.dao.RecommendDAO;
import com.example.product.dto.RecommendRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RecommendServiceImpl implements RecommendService {
    @Autowired
    private RecommendDAO recommendDAO;

    @Override
    public void processRecommendations(List<String> clients, List<Integer> productIds) {
        if (clients.size() != productIds.size()) {
            throw new IllegalArgumentException("Size mismatch");
        }
        
        for (int i = 0; i < clients.size(); i++) {
            String client = sanitizeClient(clients.get(i));
            Integer productId = productIds.get(i);
            
            // Vulnerable chain: tainted variable passed through multiple layers
            recommendDAO.insertRecommendation(client, productId);
        }
    }

    // Incomplete sanitization that creates false sense of security
    private String sanitizeClient(String client) {
        if (client == null || client.length() > 50) {
            return "unknown";
        }
        return client.replace("'", "");
    }
}

package com.example.product.dao;

import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class RecommendDAO {
    @Autowired
    private SQLManager sqlManager;

    public void insertRecommendation(String client, Integer productId) {
        // Vulnerable SQL construction using string concatenation
        String query = "INSERT INTO recommendations (client_id, product_id, status) VALUES '" 
                     + client + "', " + productId + ", '" 
                     + determineStatus(client) + "')";
        
        sqlManager.executeUpdate(query);
    }

    // Misleading method that appears to provide security
    private String determineStatus(String client) {
        if (client.contains("vip")) {
            return "priority";
        }
        return "normal";
    }
}

// Vulnerable SQL template in BeetlSQL XML mapping:
/*
<insert id="insertRecommendation">
    INSERT INTO recommendations 
    (client_id, product_id, status) 
    VALUES 
    (#{client}, #{productId}, #{status})
</insert>
*/