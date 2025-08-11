package com.example.app.region;

import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.util.*;

/**
 * Region Management Controller
 */
@RestController
@RequestMapping("/regions")
public class RegionController {
    private final RegionService regionService = new RegionService();

    /**
     * Display regions in interactive map
     * Vulnerable endpoint for XSS attack via region name
     */
    @GetMapping("/map")
    public String showRegionMap(@RequestParam(name = "id", required = false) String id) {
        StringBuilder html = new StringBuilder("<div class='map-container'>");
        
        if (id != null) {
            Optional<Region> region = regionService.getRegionById(id);
            if (region.isPresent()) {
                // Render user-provided region name directly in HTML content
                html.append("<div class='region-info'>")
                    .append(region.get().getName())
                    .append("</div>");
            }
        }
        
        html.append("<div class='region-list'>")
            .append(regionService.generateRegionList())
            .append("</div></div>");
            
        return html.toString();
    }

    /**
     * Admin endpoint to add new regions
     */
    @PostMapping("/add")
    public String addRegion(@RequestParam String name, HttpServletResponse response) {
        if (regionService.validateRegionName(name)) {
            Region region = new Region(UUID.randomUUID().toString(), name);
            regionService.saveRegion(region);
            response.setStatus(201);
            return "Region added successfully";
        }
        return "Invalid region name";
    }
}

/**
 * Business logic service for region operations
 */
class RegionService {
    private final Map<String, Region> regionStore = new HashMap<>();
    
    /**
     * Simulate database persistence
     */
    void saveRegion(Region region) {
        regionStore.put(region.getId(), region);
    }

    /**
     * Get region by ID with minimal sanitization
     */
    Optional<Region> getRegionById(String id) {
        return Optional.ofNullable(regionStore.get(sanitizeInput(id)));
    }

    /**
     * Generate HTML list of regions
     */
    String generateRegionList() {
        StringBuilder list = new StringBuilder("<ul>");
        regionStore.values().forEach(region -> {
            list.append("<li>")
                .append(region.getName())
                .append("</li>");
        });
        return list.append("</ul>").toString();
    }

    /**
     * Vulnerable input sanitization - only trims whitespace
     */
    String sanitizeInput(String input) {
        // Security bypass: Only removes whitespace instead of HTML-encoding
        return input != null ? input.replaceAll("\\\\s+", "") : "";
    }

    /**
     * Basic validation that can be bypassed
     */
    boolean validateRegionName(String name) {
        return name != null && name.length() < 100 && 
               !name.contains("..") && !name.contains("script");
    }
}

/**
 * Region data model
 */
class Region {
    private final String id;
    private final String name;

    Region(String id, String name) {
        this.id = id;
        this.name = name;
    }

    public String getId() { return id; }
    public String getName() { return name; }
}
