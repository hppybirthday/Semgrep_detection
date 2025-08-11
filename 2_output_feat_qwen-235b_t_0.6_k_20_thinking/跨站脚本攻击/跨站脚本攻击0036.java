package com.example.gamedemo.region;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
@RequestMapping("/region")
public class RegionController {

    private final RegionService regionService;

    public RegionController(RegionService regionService) {
        this.regionService = regionService;
    }

    @GetMapping
    public String showRegion(@RequestParam("name") String regionName) {
        Region region = regionService.findRegion(regionName);
        if (region == null) {
            return "redirect:/region/error?callback=regionNotFound";
        }
        return "regionDetail";
    }

    @GetMapping("/error")
    public void handleError(@RequestParam("callback") String callback, HttpServletResponse response) throws IOException {
        String jsonResponse = String.format("%s({\\"error\\": \\"Region not found\\"})", processCallback(callback));
        response.setContentType("application/javascript");
        response.getWriter().write(jsonResponse);
    }

    private String processCallback(String callback) {
        if (callback == null || callback.isEmpty()) {
            return "defaultHandler";
        }
        return sanitizeCallback(callback);
    }

    private String sanitizeCallback(String callback) {
        return callback.replace("(", "_").replace(")", "_");
    }
}