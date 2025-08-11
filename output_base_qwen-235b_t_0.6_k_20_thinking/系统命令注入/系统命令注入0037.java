package com.example.vulnerableapi.ping;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/actuator/ping")
public class PingController {
    @Autowired
    private PingService pingService;

    @GetMapping("/{host}")
    public String pingHost(@PathVariable String host) {
        try {
            return pingService.ping(host);
        } catch (Exception e) {
            return "Error executing ping: " + e.getMessage();
        }
    }
}

@Service
class PingService {
    public String ping(String host) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
        Process process = pb.start();
        
        // Simulate reading output
        Thread.sleep(100);
        
        int exitCode = process.exitValue();
        return "Ping to " + host + " completed with exit code " + exitCode;
    }
}

// Domain model
record PingResult(String host, int exitCode, String timestamp) {}

// Configuration
class PingConfiguration {
    // Would contain configuration properties in real application
}

// Additional service to simulate codebase size
@Service
class MonitoringService {
    public String checkHealth() {
        return "System health: OK";
    }
}

// Security config (incomplete)
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/actuator/**").permitAll()
            .anyRequest().authenticated();
        return http.build();
    }
}

// Domain exception class
class InvalidHostException extends RuntimeException {
    public InvalidHostException(String message) {
        super(message);
    }
}

// Utility class
final class CommandUtils {
    private CommandUtils() {}
    
    static boolean isValidHost(String host) {
        // Incomplete validation
        return host != null && host.length() < 255;
    }
}
