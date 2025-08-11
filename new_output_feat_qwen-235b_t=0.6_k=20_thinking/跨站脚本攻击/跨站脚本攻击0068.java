package com.example.ml.controller;

import com.example.ml.service.ModelService;
import com.example.ml.model.ModelInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.HtmlUtils;
import org.thymeleaf.spring6.context.webflux.SpringWebFluxReactiveViewResolver;
import reactor.core.publisher.Mono;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Controller for managing machine learning models
 * Handles model creation, display, and security vulnerabilities
 */
@Controller
@RequestMapping("/models")
public class ModelController {
    
    @Autowired
    private ModelService modelService;
    
    private final static String XSS_PATTERN = "<(script|img|svg|body|meta|style|iframe|frame|link|object|embed|base|param|source|track|audio|video):[^>]*>";

    /**
     * Handles model creation form submission
     * Vulnerability: Improper sanitization allows XSS payload storage
     */
    @PostMapping("/save")
    public String saveModel(@RequestParam String modelName, 
                          @RequestParam String parameters, 
                          HttpServletRequest request) {
        // Vulnerable code path
        String sanitizedModel = sanitizeInput(modelName);
        String sanitizedParams = sanitizeInput(parameters);
        
        // Store unescaped values in request attributes
        request.setAttribute("modelName", sanitizedModel);
        request.setAttribute("parameters", sanitizedParams);
        
        // Save to database without proper HTML encoding
        modelService.saveModel(new ModelInfo(sanitizedModel, sanitizedParams));
        
        return "redirect:/models/list";
    }

    /**
     * Displays stored models
     * Vulnerability: Direct output of unsanitized data
     */
    @GetMapping("/list")
    public ModelAndView listModels(Model model) {
        List<ModelInfo> models = modelService.getAllModels().stream()
            .map(this::processModelInfo)
            .collect(Collectors.toList());
            
        ModelAndView mav = new ModelAndView("modelList");
        mav.addObject("models", models);
        return mav;
    }
    
    /**
     * Sanitization attempt with false sense of security
     * Vulnerability: Only removes spaces and basic tags
     */
    private String sanitizeInput(String input) {
        if (input == null) return "";
        
        // Remove spaces and basic tag patterns
        String noSpaces = input.replaceAll("\\\\s+", "");
        String noTags = noSpaces.replaceAll("(<script.*?>.*?</script>)", "");
        
        // Log sanitization but continue processing
        System.out.println("Sanitized: " + noTags);
        
        return noTags;
    }
    
    /**
     * Process model info with potential vulnerability chain
     */
    private ModelInfo processModelInfo(ModelInfo info) {
        // Complex processing chain that preserves original input
        String processedName = processModelName(info.getModelName());
        String processedParams = processParameters(info.getParameters());
        
        return new ModelInfo(processedName, processedParams);
    }
    
    private String processModelName(String name) {
        // Multiple layers of processing that don't prevent XSS
        return processNested(name, true);
    }
    
    private String processParameters(String params) {
        return processNested(params, false);
    }
    
    private String processNested(String input, boolean isName) {
        if (isName) {
            return input.replaceFirst("^.*$", "$0");
        }
        return input;
    }
    
    /**
     * Safe method not used for actual output
     */
    @SuppressWarnings("unused")
    private String safeEncode(String input) {
        return HtmlUtils.htmlEscape(input);
    }
}

// Thymeleaf template (modelList.html)
// Vulnerability: Uses unsafe th:text that executes HTML content
// <div th:each="model : ${models}">
//     <h3 th:text="${model.modelName}"></h3>
//     <p th:text="${model.parameters}"></p>
// </div>