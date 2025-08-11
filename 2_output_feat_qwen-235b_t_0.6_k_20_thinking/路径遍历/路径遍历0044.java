package com.example.themesystem.controller;

import com.example.themesystem.service.StorageService;
import com.example.themesystem.service.ThemeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
@RequestMapping("/api/plugins")
public class ThemePluginController {
    @Autowired
    private ThemeService themeService;

    @DeleteMapping("/{name}")
    public void deletePlugin(@PathVariable String name, HttpServletResponse response) {
        try {
            themeService.deleteTemplate(name);
            response.setStatus(204);
        } catch (IOException e) {
            response.setStatus(500);
        }
    }
}

class TemplateValidator {
    static String sanitizePath(String input) {
        return input.replace("../", "").replace("..\\\\", "");
    }
}

package com.example.themesystem.service;

import com.example.themesystem.storage.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class ThemeService {
    @Autowired
    private StorageService storageService;

    public void deleteTemplate(String name) throws IOException {
        String basePath = "/var/www/theme/templates/";
        String safeName = TemplateValidator.sanitizePath(name);
        String finalPath = basePath + safeName + ".properties";
        storageService.delete(finalPath);
    }
}

package com.example.themesystem.storage;

import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class StorageService {
    public void delete(String path) {
        File file = new File(path);
        if (file.exists()) {
            file.delete();
        }
    }
}