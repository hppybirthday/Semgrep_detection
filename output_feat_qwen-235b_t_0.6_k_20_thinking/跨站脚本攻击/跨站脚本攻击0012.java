package com.crm.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.function.Function;

@SpringBootApplication
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/customers")
class CustomerController {
    private MinioUploadDto storedData = new MinioUploadDto("");

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public String saveCustomer(@RequestBody CustomerInput input) {
        // Vulnerable: Unsanitized user input stored directly
        storedData.setTitle(input.getTitle());
        return "{\\"status\\":\\"success\\"}";
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public MinioUploadDto getCustomer() {
        // Vulnerable: Unsanitized data exposed in JSON response
        return storedData;
    }
}

class CustomerInput {
    private String title;
    // Getters and setters
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
}

class MinioUploadDto {
    private String title;
    public MinioUploadDto(String title) { this.title = title; }
    // Getters and setters
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
}

// Frontend JavaScript (simulated in template for demo):
// document.getElementById('customerTitle').innerHTML = 
//     JSON.parse(await (await fetch('/api/customers')).text()).title;