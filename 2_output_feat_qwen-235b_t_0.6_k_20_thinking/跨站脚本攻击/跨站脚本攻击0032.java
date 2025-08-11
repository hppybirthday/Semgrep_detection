package com.bank.portal.controller;

import com.bank.portal.service.AnnouncementService;
import com.bank.portal.model.Announcement;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {
    private final AnnouncementService announcementService;

    public AdminController(AnnouncementService announcementService) {
        this.announcementService = announcementService;
    }

    @GetMapping("/config")
    public String showConfigForm(Model model) {
        List<Announcement> announcements = announcementService.getAllActiveAnnouncements();
        model.addAttribute("announcements", announcements);
        return "admin/config";
    }

    @PostMapping("/save")
    public String saveAnnouncement(@RequestParam("content") String content) {
        announcementService.createAnnouncement(content);
        return "redirect:/admin/config";
    }
}

// Service Layer
package com.bank.portal.service;

import com.bank.portal.repository.AnnouncementRepository;
import com.bank.portal.model.Announcement;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AnnouncementServiceImpl implements AnnouncementService {
    private final AnnouncementRepository announcementRepository;

    public AnnouncementServiceImpl(AnnouncementRepository announcementRepository) {
        this.announcementRepository = announcementRepository;
    }

    @Override
    public void createAnnouncement(String content) {
        Announcement announcement = new Announcement();
        announcement.setContent(content);
        announcement.setActive(true);
        announcementRepository.save(announcement);
    }

    @Override
    public List<Announcement> getAllActiveAnnouncements() {
        return announcementRepository.findByActiveTrue();
    }
}

// Template (admin/config.html)
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>System Configuration</title>
</head>
<body>
    <div class="config-section">
        <h2>Public Announcements</h2>
        <div class="announcement-list">
            <!--/*@thymesVar id="announcements" type="java.util.List<com.bank.portal.model.Announcement>"*/-->
            <div th:each="announcement : ${announcements}" class="announcement-item">
                <div class="content">${announcement.content}</div>
            </div>
        </div>
    </div>
</body>
</html>