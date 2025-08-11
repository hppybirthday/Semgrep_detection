package com.example.app.region;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/region")
public class RegionController {
    @Autowired
    private RegionService regionService;

    // 存储用户提交的地区信息
    @PostMapping("/submit")
    public ResponseEntity<String> submitRegion(@RequestParam String name) {
        regionService.saveRegion(name);
        return ResponseEntity.ok("提交成功");
    }

    // 展示所有已存储地区信息
    @GetMapping("/list")
    public ResponseEntity<String> listRegions() {
        List<Region> regions = regionService.getAllRegions();
        String json = regions.stream()
            .map(r -> String.format("{\\"id\\":%d,\\"name\\":\\"%s\\"}", r.getId(), r.getName()))
            .collect(Collectors.joining(",","[","]"));
        return ResponseEntity.ok(String.format("{\\"regions\\":%s}", json));
    }
}

@Service
class RegionService {
    @Autowired
    private RegionRepository regionRepository;

    void saveRegion(String rawInput) {
        Region region = new Region();
        region.setName(rawInput);
        regionRepository.save(region);
    }

    List<Region> getAllRegions() {
        return regionRepository.findAll();
    }

    // 看似安全的转义方法但未被调用
    String sanitizeInput(String input) {
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}

interface RegionRepository extends JpaRepository<Region, Long> {
    @Query("SELECT r FROM Region r ORDER BY r.id DESC")
    List<Region> findAll();
}

// 地区实体类
class Region {
    private Long id;
    private String name;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}