package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import javax.persistence.*;
import java.util.*;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@Entity
class Region {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}

interface RegionRepository extends JpaRepository<Region, Long> {}

@Service
class RegionService {
    @Autowired
    private RegionRepository repository;
    
    public Map<String, Object> createRegion(String name) {
        Region region = new Region();
        region.setName(name);
        Region saved = repository.save(region);
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Region " + name + " created successfully");
        response.put("data", saved);
        return response;
    }
}

@RestController
@RequestMapping("/regions")
class RegionController {
    @Autowired
    private RegionService service;
    
    @PostMapping
    public Map<String, Object> addRegion(@RequestParam String name) {
        return service.createRegion(name);
    }
    
    @GetMapping
    public List<Region> getAll() {
        return repository.findAll();
    }
}