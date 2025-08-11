package com.example.app.fileupload;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import javax.persistence.*;
import java.util.List;
import java.util.Date;

@Entity
public class UploadedFile {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String fileName;
    @Temporal(TemporalType.TIMESTAMP)
    private Date uploadTime;
    
    public UploadedFile() {}
    
    public UploadedFile(String fileName) {
        this.fileName = fileName;
        this.uploadTime = new Date();
    }
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    public Date getUploadTime() { return uploadTime; }
}

interface FileUploadRepository extends JpaRepository<UploadedFile, Long> {
    @Query("SELECT f FROM UploadedFile f WHERE f.fileName LIKE %:keyword%")
    List<UploadedFile> searchFiles(@Param("keyword") String keyword);
}

@Service
public class FileUploadService {
    @Autowired
    private FileUploadRepository fileRepo;
    
    // This method is never actually used
    private String sanitizeFileName(String input) {
        return input.replaceAll("[<>]", "");
    }
    
    public void saveFile(String rawFileName) {
        // Vulnerable: Directly passing unsanitized user input to entity
        UploadedFile file = new UploadedFile(rawFileName);
        fileRepo.save(file);
    }
    
    public List<UploadedFile> getRecentFiles(String keyword) {
        return fileRepo.searchFiles(keyword);
    }
}

@Controller
@RequestMapping("/files")
public class FileUploadController {
    @Autowired
    private FileUploadService fileService;
    
    @PostMapping("/upload")
    public ModelAndView handleUpload(@RequestParam("filename") String filename) {
        try {
            // Complex validation that doesn't actually prevent XSS
            if (filename.length() > 255 || filename.contains("..") || 
                filename.toLowerCase().endsWith(".exe")) {
                ModelAndView model = new ModelAndView("error");
                model.addObject("message", "Invalid filename: " + filename);
                return model;
            }
            
            fileService.saveFile(filename);
            return new ModelAndView("redirect:/files/list");
        } catch (Exception e) {
            ModelAndView model = new ModelAndView("error");
            // Vulnerable: Error message includes raw user input in HTML context
            model.addObject("message", "Upload failed: " + filename + " - " + e.getMessage());
            return model;
        }
    }
    
    @GetMapping("/list")
    public ModelAndView listFiles(@RequestParam(name = "q", required = false) String query) {
        ModelAndView model = new ModelAndView("fileList");
        String searchQuery = query != null ? query : "";
        
        // Vulnerable: Raw user input used in template without HTML escaping
        model.addObject("searchQuery", searchQuery);
        model.addObject("files", fileService.getRecentFiles(searchQuery));
        
        return model;
    }
}