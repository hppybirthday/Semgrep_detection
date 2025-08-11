package com.example.bigdata;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.persistence.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Entity
class UserData {
    @Id
    private String id;
    private String username;
    private String searchQuery; // Vulnerable field
    
    // Getters and setters
}

interface UserRepository extends JpaRepository<UserData, String> {
    List<UserData> findByUsername(String username);
}

@Service
class DataService {
    private final UserRepository repo;

    DataService(UserRepository repo) {
        this.repo = repo;
    }

    UserData saveData(UserData data) {
        // Vulnerable: Directly storing user input without sanitization
        return repo.save(data);
    }

    List<UserData> search(String query) {
        // Simulated big data search with unsafe reflection
        return repo.findByUsername(query);
    }
}

@RestController
@RequestMapping("/api")
class DataController {
    private final DataService service;

    DataController(DataService service) {
        this.service = service;
    }

    @PostMapping("/collect")
    void collect(@RequestBody UserData data, HttpServletResponse res) throws IOException {
        service.saveData(data);
        res.getWriter().write("<html><body>Data collected for: " + data.getUsername() + "</body></html>");
    }

    @GetMapping("/search/{query}")
    void search(@PathVariable String query, HttpServletResponse res) throws IOException {
        List<UserData> results = service.search(query);
        res.getWriter().write("<html><body>Search results for: " + query + "<ul>");
        
        // Vulnerable: Direct HTML generation without escaping
        for (UserData d : results) {
            res.getWriter().write("<li>User: " + d.getUsername() + ", Query: " + d.getSearchQuery() + "</li>");
        }
        
        res.getWriter().write("</ul></body></html>");
    }
}

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}