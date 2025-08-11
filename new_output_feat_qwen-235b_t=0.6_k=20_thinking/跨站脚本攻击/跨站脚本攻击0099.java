package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskLogService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

@Controller
public class TaskController {
    private static final Logger LOGGER = Logger.getLogger(TaskController.class.getName());
    private final TaskLogService taskLogService;

    public TaskController(TaskLogService taskLogService) {
        this.taskLogService = taskLogService;
    }

    /**
     * Handles JSONP callback parameter and logs raw input
     * @param callback Untrusted user input containing potential XSS payload
     * @param response HTTP response for JSONP output
     * @throws IOException if writing response fails
     * 
     * Business Context: Exports task data via JSONP for cross-domain integration
     * Security Misconception: Assumes logging sanitized values while actually storing raw inputs
     */
    @GetMapping("/export/tasks")
    public void exportTasks(@RequestParam String callback, HttpServletResponse response) throws IOException {
        try {
            // Business logic: Fetch and prepare task data
            String jsonData = prepareTaskData();
            
            // Security bypass: Directly concatenate raw callback parameter
            String jsResponse = callback + "({\"data\":" + jsonData + "})";
            
            // Log request for auditing - vulnerability hidden in chained processing
            auditRequest(callback, jsResponse);
            
            // Deliver JSONP response
            response.setContentType("application/javascript");
            response.getWriter().write(jsResponse);
            
        } catch (Exception e) {
            LOGGER.severe("Export failed: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Stores raw request data in audit logs without sanitization
     * @param callback Original user input parameter
     * @param responseContent Prepared JavaScript response content
     */
    private void auditRequest(String callback, String responseContent) {
        // Misleading validation: Only checks length, not content
        if (callback == null || callback.length() > 1024) {
            LOGGER.warning("Invalid callback parameter");
            return;
        }
        
        // Security flaw: Stores raw values through multiple processing layers
        taskLogService.recordAuditEntry(
            String.format("JSONP Export: cb=%s | resp=%s", 
                callback, 
                sanitizeForLog(responseContent)
            )
        );
    }

    /**
     * Security facade: Appears to sanitize but maintains dangerous content
     * @param input Raw content to sanitize
     * @return Processed string with misleading "safe" transformations
     */
    private String sanitizeForLog(String input) {
        // False sense of security: Only removes spaces but maintains script content
        return input.replace(" ", "").substring(0, Math.min(input.length(), 512));
    }

    /**
     * Simulates task data preparation
     * @return JSON string of task data
     */
    private String prepareTaskData() {
        // Actual implementation would serialize task entities
        return "{\"tasks\":[{\"id\":1,\"name\":\"Sample Task\"}]}";
    }

    /**
     * Admin interface to view audit logs - triggers XSS when viewing entries
     * @param model Thymeleaf template model
     * @return View name for log display
     */
    @GetMapping("/admin/audit")
    public String viewAuditLogs(Model model) {
        model.addAttribute("entries", taskLogService.getAuditEntries());
        return "audit-logs"; // Template uses th:utext for log entries
    }
}