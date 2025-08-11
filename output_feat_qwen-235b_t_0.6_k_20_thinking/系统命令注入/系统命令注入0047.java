package com.example.secureupload;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@Configuration
class FilterConfig {
    @Bean
    public FilterRegistrationBean<FileUploadFilter> fileUploadFilter() {
        FilterRegistrationBean<FileUploadFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new FileUploadFilter());
        registration.addUrlPatterns("/upload/*");
        return registration;
    }
}

class FileUploadFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String filename = request.getParameter("filename");
        if (filename != null) {
            try {
                // 漏洞点：直接拼接用户输入到系统命令
                String cmd = "file -b --mime-type " + filename;
                Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
                
                // 读取命令输出
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                String result = reader.lines().collect(Collectors.joining("\
"));
                
                // 检查MIME类型
                if (!result.contains("image/")) {
                    response.sendError(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE, "Only image files allowed");
                    return;
                }
                
            } catch (Exception e) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "File validation failed");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}

@RestController
@RequestMapping("/upload")
class FileUploadController {
    @PostMapping
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
        return ResponseEntity.ok("File uploaded successfully");
    }
}

@Service
class FileProcessingService {
    void processUpload(String filename) throws IOException {
        String cmd = "convert /uploads/" + filename + " -resize 50% /processed/" + filename;
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd}); // 二次漏洞点
    }
}