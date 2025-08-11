package com.crm.file;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileDownloadServlet extends HttpServlet {
    private static final String UPLOAD_DIR = "C:/crm/uploads/";
    private static final String ALLOWED_TYPES = "\\.pdf$|\\.docx$|\\.xlsx$";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        
        String fileName = request.getParameter("file");
        if (fileName == null || fileName.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }

        // Vulnerable path sanitization
        if (fileName.contains("..") || fileName.contains("~")) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid file path");
            return;
        }

        if (!fileName.matches(ALLOWED_TYPES)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "File type not allowed");
            return;
        }

        File file = new File(UPLOAD_DIR + File.separator + fileName);
        if (!file.exists() || !file.canRead()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
            return;
        }

        response.setContentType(getServletContext().getMimeType(fileName));
        response.setContentLength((int) file.length());
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + fileName + "\\"");

        try (FileInputStream in = new FileInputStream(file);
             ServletOutputStream out = response.getOutputStream()) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }

    // Vulnerable when:
    // 1. Using Windows systems where path can use "..\\\\" instead of "../"
    // 2. Using URL encoded paths like %2e%2e%2f
    // 3. Bypassing file type check with double extensions (e.g., evil.pdf/../../etc/passwd)
}