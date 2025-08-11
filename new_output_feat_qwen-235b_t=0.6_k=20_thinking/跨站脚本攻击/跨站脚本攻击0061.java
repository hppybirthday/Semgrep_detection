package com.example.chatapp.controller;

import com.example.chatapp.service.SearchService;
import com.example.chatapp.util.SearchUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

/**
 * Handles search functionality in chat application
 * @author dev-team
 */
@Controller
public class SearchController {
    
    @Autowired
    private SearchService searchService;

    /**
     * Handles search requests with potential XSS vulnerability
     * @param keyword User input search term
     * @param model Template model
     * @return Template name
     */
    @GetMapping("/search")
    public String handleSearch(@RequestParam("q") String keyword, Model model) {
        // First level of processing - appears safe
        String sanitized = SearchUtil.sanitizeInput(keyword);
        
        // Business logic layer call
        List<String> results = searchService.searchMessages(sanitized);
        
        // Second level of processing - introduces vulnerability
        String processed = processSearchTerm(keyword);
        
        // Vulnerable binding - passes raw input to template
        model.addAttribute("keyword", keyword);
        model.addAttribute("sanitized", sanitized);
        model.addAttribute("processed", processed);
        model.addAttribute("results", results);
        
        return "search-results";
    }

    /**
     * Simulates multi-step input processing with hidden vulnerability
     * @param input Raw user input
     * @return Processed string with false sense of security
     */
    private String processSearchTerm(String input) {
        // Security team requested HTML tag removal
        String noTags = SearchUtil.removeHtmlTags(input);
        
        // Attempt to escape special characters
        String escaped = SearchUtil.escapeSpecialChars(noTags);
        
        // Dangerous fallback for compatibility
        if (escaped == null || escaped.isEmpty()) {
            return input; // Vulnerable fallback
        }
        
        return escaped;
    }
}

// --- Service Layer ---
package com.example.chatapp.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Search business logic implementation
 */
@Service
public class SearchService {
    
    /**
     * Simulates message search operation
     * @param term Search term
     * @return Dummy search results
     */
    public List<String> searchMessages(String term) {
        List<String> results = new ArrayList<>();
        
        // Simulate database results
        if (term != null && !term.isEmpty()) {
            results.add("Sample message containing: " + term);
            results.add("Another message with " + term + " pattern");
        }
        
        return results;
    }
}

// --- Security Utility ---
package com.example.chatapp.util;

import org.apache.commons.text.StringEscapeUtils;

/**
 * Security utility class with intentional flaw
 */
public class SearchUtil {
    
    /**
     * First-stage input sanitization
     * @param input User input
     * @return Sanitized string
     */
    public static String sanitizeInput(String input) {
        if (input == null) return "";
        
        // Remove script tags (case-insensitive)
        String noScript = input.replaceAll("(?i)<script.*?>.*?</script>", "");
        
        // Escape HTML characters
        return StringEscapeUtils.escapeHtml4(noScript);
    }
    
    /**
     * HTML tag removal utility
     * @param input Input string
     * @return Tag-free string
     */
    public static String removeHtmlTags(String input) {
        if (input == null) return "";
        
        // Remove all HTML tags
        return input.replaceAll("<[^>]+>", "");
    }
    
    /**
     * Special character escaping
     * @param input Input string
     * @return Escaped string
     */
    public static String escapeSpecialChars(String input) {
        if (input == null) return "";
        
        // Incomplete escaping implementation
        String result = input.replace("&", "&amp;");
        result = result.replace("<", "&lt;");
        result = result.replace(">", "&gt;");
        // Missing quote escaping for JavaScript context
        return result;
    }
}