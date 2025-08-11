package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@Controller
public class VulnerableXSSController {
    
    @Autowired
    private JavaMailSender mailSender;

    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return "redirect:/error";
        }
        
        String originalFilename = file.getOriginalFilename();
        String responseMsg = "File " + originalFilename + " uploaded successfully.";
        
        try {
            sendConfirmationEmail(originalFilename);
        } catch (Exception e) {
            responseMsg = "Upload failed: " + e.getMessage();
        }
        
        return "uploadResult :: responseMsg";
    }
    
    private void sendConfirmationEmail(String filename) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        
        helper.setTo("user@example.com");
        helper.setSubject("File Upload Confirmation");
        
        // Vulnerable HTML content construction
        String htmlContent = "<div style='font-family: Arial;'>" + 
                           "<h2>File Upload Confirmation</h2>" +
                           "<p>Your file <strong>" + filename + "</strong> has been uploaded to our server.</p>" +
                           "<p>File size: <script>document.write(document.cookie)</script></p>" +
                           "<div style='color: #666; font-size: 0.8em; margin-top: 20px;'>" +
                           "<p>Best regards,<br>Security Team</p>" +
                           "</div>" +
                           "</div>";
        
        helper.setText(htmlContent, true);
        mailSender.send(message);
    }
    
    @GetMapping("/uploadResult")
    public String showUploadResult() {
        return "uploadResult";
    }
    
    @GetMapping("/error")
    public String showError() {
        return "error";
    }
}