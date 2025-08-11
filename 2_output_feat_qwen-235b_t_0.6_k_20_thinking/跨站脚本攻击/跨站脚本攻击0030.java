package com.example.mlapp.controller;

import com.example.mlapp.model.Region;
import com.example.mlapp.repository.RegionRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;

@Controller
public class ErrorController {
    private final RegionRepository regionRepository;

    public ErrorController(RegionRepository regionRepository) {
        this.regionRepository = regionRepository;
    }

    @GetMapping("/error")
    public String showErrorPage(@RequestParam String regionName, Model model) {
        Optional<Region> region = regionRepository.findByRegionName(regionName);
        
        if (region.isPresent()) {
            model.addAttribute("errorInfo", "Region data: " + region.get().getRegionName());
            return "errorTemplate";
        }
        
        // 构造包含用户输入的错误提示
        String errorMsg = String.format("Region '%s' not found in database", regionName);
        model.addAttribute("errorInfo", errorMsg);
        return "errorTemplate";
    }
}