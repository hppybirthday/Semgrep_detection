package com.example.xssdemo.application;

import com.example.xssdemo.domain.EmailService;
import com.example.xssdemo.domain.UserProfile;
import com.example.xssdemo.domain.UserProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.util.Optional;

@RestController
@RequestMapping("/api/emails")
public class EmailController {
    
    @Autowired
    private JavaMailSender mailSender;
    
    @Autowired
    private UserProfileRepository userProfileRepo;
    
    @GetMapping("/send")
    public String sendEmail(@RequestParam String userId, 
                           @RequestParam String subject, 
                           @RequestParam String content) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            
            Optional<UserProfile> user = userProfileRepo.findById(userId);
            if (!user.isPresent()) {
                return "User not found";
            }
            
            String emailContent = EmailService.generateEmailContent(
                user.get().getName(), 
                subject, 
                content
            );
            
            helper.setTo(user.get().getEmail());
            helper.setSubject("[XSS] " + subject);
            helper.setText(emailContent, true);
            
            mailSender.send(message);
            return "Email sent successfully";
            
        } catch (MessagingException e) {
            return "Failed to send email: " + e.getMessage();
        }
    }
}

// EmailService.java
package com.example.xssdemo.domain;

public class EmailService {
    public static String generateEmailContent(String recipient, 
                                            String subject, 
                                            String content) {
        return "<html>
            <body>
                <h1>Dear " + recipient + ",</h1>
                <h2>" + subject + "</h2>
                <p>" + content + "</p>
                <div style='color: gray; font-size: 0.8em;'>
                    This email was sent from your account
                </div>
            </body>
        </html>";
    }
}

// UserProfile.java
package com.example.xssdemo.domain;

public class UserProfile {
    private String id;
    private String name;
    private String email;
    // getters/setters
}

// Repository
package com.example.xssdemo.domain;

import org.springframework.data.repository.CrudRepository;
public interface UserProfileRepository extends CrudRepository<UserProfile, String> {}