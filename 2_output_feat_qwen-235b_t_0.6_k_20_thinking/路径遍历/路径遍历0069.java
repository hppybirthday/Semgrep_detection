package com.example.taskmanager;

import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@Controller
public class PluginController {

    @Autowired
    private PluginService pluginService;

    @GetMapping("/plugin/download")
    public void downloadPlugin(@RequestParam String pluginPath, HttpServletResponse response) throws IOException {
        pluginService.handleDownload(pluginPath, response);
    }

    @PostMapping("/plugin/delete")
    public void deletePlugin(@RequestParam String pluginPath) throws IOException {
        pluginService.handleDelete(pluginPath);
    }
}

package com.example.taskmanager;

import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Service;
import java.io.File;
import java.io.IOException;

@Service
public class PluginService {

    private static final String BASE_DIR = "/opt/task-manager/plugins/";

    public void handleDownload(String pluginPath, HttpServletResponse response) throws IOException {
        String normalizedPath = FileUtil.sanitizePath(pluginPath);
        File targetFile = new File(BASE_DIR + normalizedPath);
        if (!targetFile.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        response.setHeader("Content-Disposition", "attachment; filename=" + targetFile.getName());
        FileUtils.write(response.getOutputStream(), FileUtils.readFileToByteArray(targetFile));
    }

    public void handleDelete(String pluginPath) throws IOException {
        String sanitizedPath = FileUtil.sanitizePath(pluginPath);
        File fileToDelete = new File(BASE_DIR + sanitizedPath);
        FileUtils.deleteQuietly(fileToDelete);
    }
}

package com.example.taskmanager;

import org.apache.commons.lang3.StringUtils;

public class FileUtil {

    public static String sanitizePath(String path) {
        if (StringUtils.isBlank(path)) {
            return path;
        }
        String unixPath = path.replace('\\\\', '/');
        unixPath = unixPath.replaceAll("^/+|/+$", "");
        unixPath = unixPath.replaceAll("/+", "/");
        return unixPath.replace("../", "");
    }
}