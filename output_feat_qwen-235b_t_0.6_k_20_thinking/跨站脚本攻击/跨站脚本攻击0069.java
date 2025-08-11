package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssApplication.class, args);
    }

    @Bean
    public AdService adService() {
        return new AdService();
    }
}

@Controller
class AdController {
    private final AdService adService;

    public AdController(AdService adService) {
        this.adService = adService;
    }

    @GetMapping("/ads")
    public ModelAndView viewAds() {
        ModelAndView mav = new ModelAndView("ads");
        mav.addObject("ads", adService.getAllAds());
        return mav;
    }

    @PostMapping("/ads")
    public String createAd(@RequestParam String content) {
        adService.addAd(content);
        return "redirect:/ads";
    }
}

class AdService {
    private final List<String> adRepository = new ArrayList<>();

    public void addAd(String content) {
        // 模拟存储前未进行任何输入验证
        adRepository.add(content);
    }

    public List<String> getAllAds() {
        return List.copyOf(adRepository);
    }
}

// src/main/resources/templates/ads.jsp
// <%@ page contentType="text/html;charset=UTF-8" %>
// <html>
// <body>
// <h1>Advertisements</h1>
// <div id="ads">
//     ${ads.stream().map(ad -> "<div class='ad'>" + ad + "</div>").reduce((a, b) -> a + b).orElse("")}
// </div>
// <form method="post" action="/ads">
//     <textarea name="content"></textarea>
//     <button type="submit">Submit Ad</button>
// </form>
// </body>
// </html>