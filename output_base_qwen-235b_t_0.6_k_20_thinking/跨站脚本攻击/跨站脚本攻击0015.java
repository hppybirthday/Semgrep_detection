package com.example.xss;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@SpringBootApplication
public class XssApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssApplication.class, args);
    }
}

@RestController
class XssController {
    @Autowired
    private GreetingService greetingService;

    @GetMapping("/greet")
    public void greet(@RequestParam String name, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.write("<html><body>");
        out.write(greetingService.generateGreeting(name));
        out.write("</body></html>");
    }
}

@Service
class GreetingService {
    String generateGreeting(String name) {
        return "<div class='greeting'>Hello " + name + "!</div>";
    }
}

@Configuration
class SecurityConfig {
    // 错误地认为Spring Security会自动处理XSS
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/public/**");
    }
}