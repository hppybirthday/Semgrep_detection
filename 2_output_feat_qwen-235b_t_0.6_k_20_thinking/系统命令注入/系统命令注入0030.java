package com.crm.scheduler.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;
import java.util.logging.Logger;

@RestController
public class ScheduledTaskController {

    private static final Logger LOGGER = Logger.getLogger(ScheduledTaskController.class.getName());

    @PostMapping("/admin/configure-backup")
    public String configureBackup(@RequestParam String cmd_) throws IOException {
        try {
            BackupConfig config = parseConfig(cmd_);
            runBackup(config);
            return "Backup configured successfully";
        } catch (Exception e) {
            LOGGER.severe("Backup configuration failed: " + e.getMessage());
            return "Configuration failed";
        }
    }

    private BackupConfig parseConfig(String input) {
        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException("Input cannot be empty");
        }
        return new BackupConfig(input);
    }

    private void runBackup(BackupConfig config) throws IOException {
        String[] cmdArray = buildCommandArray(config);
        Process process = Runtime.getRuntime().exec(cmdArray);
    }

    private String[] buildCommandArray(BackupConfig config) {
        return new String[]{"sh", "-c", "/opt/scripts/backup.sh --target " + config.getCustomParam()};
    }

    private static class BackupConfig {
        private final String customParam;

        public BackupConfig(String customParam) {
            this.customParam = customParam;
        }

        public String getCustomParam() {
            return customParam;
        }
    }
}