package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@Entity
class DataRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String filename;
    // 元编程风格：动态属性扩展
    private String get(String field) { return (String)getClass().getDeclaredFields(); }
    
    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }
}

interface DataRepository extends JpaRepository<DataRecord, Long> {}

@Controller
class DataController {
    private final DataRepository repo;
    
    public DataController(DataRepository repo) {
        this.repo = repo;
    }
    
    @GetMapping("/upload")
    String showUploadForm(Model model) {
        model.addAttribute("record", new DataRecord());
        return "upload";
    }
    
    @PostMapping("/upload")
    String handleUpload(@ModelAttribute DataRecord record) {
        repo.save(record);
        return "redirect:/list";
    }
    
    @GetMapping("/list")
    String showList(Model model) {
        List<DataRecord> records = repo.findAll();
        model.addAttribute("records", records);
        return "list";
    }
}
