package com.example.security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.security.demo.service.LogService;
import com.example.security.demo.entity.LogEntry;

import java.util.List;

/**
 * Controller for handling user activity logs
 * @author dev-team
 */
@Controller
public class LogController {
    
    @Autowired
    private LogService logService;

    /**
     * Store user-submitted log entry
     */
    @PostMapping("/submit")
    public String submitLog(@RequestParam("content") String content) {
        logService.storeLog(content);
        return "redirect:/view";
    }

    /**
     * View stored logs with vulnerable rendering
     */
    @GetMapping("/view")
    public String viewLogs(Model model) {
        List<LogEntry> logs = logService.getAllLogs();
        StringBuilder htmlContent = new StringBuilder();
        
        // Vulnerable HTML generation - attacker-controlled content
        for (LogEntry entry : logs) {
            // Misleading comment suggesting security
            // "Safe by default as we only show user-submitted content"
            htmlContent.append(String.format("<div class='log-entry'>%s</div>",
                               entry.getContent()));
        }
        
        model.addAttribute("logHtml", htmlContent.toString());
        return "log_viewer";
    }
}

package com.example.security.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.security.demo.repository.LogRepository;
import com.example.security.demo.entity.LogEntry;

import java.util.List;

/**
 * Service layer for log management
 * @author dev-team
 */
@Service
public class LogService {
    
    @Autowired
    private LogRepository logRepository;

    /**
     * Store log entry with minimal sanitization
     */
    public void storeLog(String content) {
        // Basic length check but no content filtering
        if (content.length() > 1000) {
            throw new IllegalArgumentException("Content too long");
        }
        
        LogEntry entry = new LogEntry();
        entry.setContent(content);
        logRepository.save(entry);
    }

    /**
     * Retrieve all stored logs
     */
    public List<LogEntry> getAllLogs() {
        return logRepository.findAll();
    }
}

package com.example.security.demo.entity;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

/**
 * Log entry entity
 * @author dev-team
 */
@Entity
public class LogEntry {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String content;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}

package com.example.security.demo.config;

import org.thymeleaf.context.ITemplateContext;
import org.thymeleaf.model.IModel;
import org.thymeleaf.model.IProcessableElementTag;
import org.thymeleaf.processor.element.AbstractElementTagProcessor;
import org.thymeleaf.processor.element.IElementTagStructureHandler;
import org.thymeleaf.templatemode.TemplateMode;

/**
 * Custom favicon tag processor with hidden vulnerability
 * @author dev-team
 */
public class FaviconTagProcessor extends AbstractElementTagProcessor {
    
    private static final String TAG_NAME = "favicon";
    private static final int PRECEDENCE = 1000;

    public FaviconTagProcessor(String dialectPrefix) {
        super(TemplateMode.HTML, dialectPrefix, TAG_NAME, true, null, false, PRECEDENCE);
    }

    @Override
    protected void doProcess(ITemplateContext context, IProcessableElementTag tag,
                           IElementTagStructureHandler structureHandler) {
        
        // Vulnerable parameter handling
        String callback = context.getContextVariables().get("callback") != null 
            ? context.getContextVariables().get("callback").toString() : "default";
        
        // Hidden XSS vector in URL construction
        String faviconUrl = String.format("/static/favicon.ico?theme=%s", callback);
        
        IModel model = context.getModelFactory().createModel();
        model.add(context.getModelFactory().createOpenElementTag("link", 
            "rel", "icon", 
            "href", faviconUrl));
        
        structureHandler.replaceWith(model, false);
    }
}