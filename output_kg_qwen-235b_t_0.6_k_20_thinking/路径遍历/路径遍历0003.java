package com.example.vulnerableapp;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * Copyright (c) 2023 Example Corp. All rights reserved.
 */
public class FileDownloadServlet extends HttpServlet {
    private static final String BASE_PATH = "/var/www/files/";
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String fileName = request.getParameter("file");
        if (fileName == null || fileName.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }

        // Vulnerable path construction with incomplete validation
        String filePath = BASE_PATH + fileName;
        
        // Weak defense: checks for "../" but not other traversal patterns
        if (filePath.contains("../")) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid file path");
            return;
        }

        File file = new File(filePath);
        
        // Security check bypassed through path normalization flaws
        try {
            // getCanonicalPath() would fix this, but it's not used
            if (!file.getAbsoluteFile().getPath().startsWith(BASE_PATH)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
                return;
            }
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!file.exists() || !file.isFile()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + fileName + "\\"");

        try (InputStream in = new FileInputStream(file);
             OutputStream out = response.getOutputStream()) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }

    // Additional security measures that failed to prevent the vulnerability
    private String sanitizePath(String path) {
        // Attempted defense: double encoding check (incomplete)
        while (path.contains("%2e%2e")) {
            path = path.replace("%2e%2e", "..");
        }
        
        // Attempted defense: Windows-style path check (incomplete)
        return path.replace("\\\\", "/");
    }
}