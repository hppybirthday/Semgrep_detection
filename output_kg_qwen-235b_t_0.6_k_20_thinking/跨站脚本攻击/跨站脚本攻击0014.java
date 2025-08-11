package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@Controller
public class XssVulnerableApp {
    private static final ConcurrentHashMap<String, String> userProfiles = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }

    @GetMapping("/profile")
    public void showProfile(@RequestParam String user, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // 模拟数据库查询
        String bio = userProfiles.getOrDefault(user, "No profile found for " + user);
        
        out.println("<html><body>");
        out.println("<h1>User Profile: " + user + "</h1>");
        out.println("<div id='bio'>" + bio + "</div>");
        out.println("<script>");
        out.println("    // Simulated client-side tracking script");
        out.println("    console.log('Viewed profile: '" + user + "');");
        out.println("</script>");
        out.println("</body></html>");
    }

    @PostMapping("/update")
    public String updateProfile(@RequestParam String user, @RequestParam String bio) {
        // Store user input without sanitization
        userProfiles.put(user, bio);
        return "redirect:/profile?user=" + user;
    }

    @GetMapping("/search")
    public void searchProfiles(@RequestParam String query, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        out.println("<h2>Search Results for '" + query + "'</h2>");
        out.println("<ul>");
        
        // Simulated search functionality with XSS propagation
        userProfiles.forEach((user, bio) -> {
            if (user.contains(query) || bio.contains(query)) {
                out.println("<li><a href='/profile?user=" + user + "'>" + user + "</a></li>");
            }
        });
        
        out.println("</ul>");
        out.println("</body></html>");
    }
}