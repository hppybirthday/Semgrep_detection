package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@SpringBootApplication
public class XssDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssDemoApplication.class, args);
    }
}

@Controller
class RegionController {
    private final RegionService regionService = new RegionService();

    @GetMapping("/region")
    public String getRegionInfo(@RequestParam String name, Model model) {
        try {
            Region region = regionService.getRegionByName(name);
            model.addAttribute("region", region);
            return "region-detail";
        } catch (InvalidRegionException e) {
            model.addAttribute("error", e.getMessage());
            model.addAttribute("regionName", name);
            return "error-page";
        }
    }
}

class RegionService {
    public Region getRegionByName(String name) {
        if (name == null || name.isEmpty() || name.contains("<") || name.contains(">")) {
            throw new InvalidRegionException("Region name \\"" + name + "\\" not found");
        }
        return new Region(name, "Cloud infrastructure zone");
    }
}

class InvalidRegionException extends RuntimeException {
    public InvalidRegionException(String message) {
        super(message);
    }
}

class Region {
    private final String name;
    private final String description;

    public Region(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }
}