package com.example.iot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class XssIotApp {
    public static void main(String[] args) {
        SpringApplication.run(XssIotApp.class, args);
    }
}

@Entity
class Device {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String status;
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}

interface DeviceRepository extends JpaRepository<Device, Long> {}

@Controller
class DeviceController {
    @Autowired
    DeviceRepository deviceRepo;

    @GetMapping("/devices")
    public String listDevices(Model model) {
        List<Device> devices = deviceRepo.findAll();
        model.addAttribute("devices", devices);
        return "devices";
    }

    @PostMapping("/addDevice")
    public String addDevice(@RequestParam String name, @RequestParam String status) {
        Device device = new Device();
        device.setName(name);
        device.setStatus(status);
        deviceRepo.save(device);
        return "redirect:/devices";
    }

    @GetMapping("/add-device-form")
    public String showAddForm() {
        return "add-device";
    }
}