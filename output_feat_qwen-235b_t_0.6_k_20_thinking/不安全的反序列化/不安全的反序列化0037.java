package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;
import java.util.List;

@SpringBootApplication
@ComponentScan
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

class Role {
    private String name;
    private String roleDependencies; // Base64 encoded serialized object

    public Role() {}

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getRoleDependencies() { return roleDependencies; }
    public void setRoleDependencies(String roleDependencies) { this.roleDependencies = roleDependencies; }
}

@Service
class RoleService {
    public void processRoleDependencies(String roleDependencies) throws Exception {
        byte[] data = Base64.getDecoder().decode(roleDependencies);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            Object obj = ois.readObject();
            // 假设预期是List<String>，但攻击者可以注入其他类型
            if (obj instanceof List) {
                // 处理逻辑
            }
        }
    }
}

@RestController
@RequestMapping("/roles")
class RoleController {
    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @PostMapping("/batch-set-status")
    public ResponseEntity<String> batchSetStatus(@RequestBody Role role) {
        try {
            roleService.processRoleDependencies(role.getRoleDependencies());
            return ResponseEntity.ok("Dependencies processed successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error processing dependencies: " + e.getMessage());
        }
    }
}