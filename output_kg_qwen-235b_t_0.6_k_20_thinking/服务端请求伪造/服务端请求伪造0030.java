package com.example.vulnerableapp;

import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ImageUploadServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String imageURL = request.getParameter("imageURL");
        if (imageURL == null || imageURL.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing imageURL parameter");
            return;
        }

        try {
            URL url = new URL(imageURL);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to download image");
                return;
            }

            InputStream inputStream = connection.getInputStream();
            File outputFile = new File("/var/www/images/" + System.currentTimeMillis() + ".jpg");
            FileOutputStream outputStream = new FileOutputStream(outputFile);

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }

            inputStream.close();
            outputStream.close();
            connection.disconnect();

            response.getWriter().write("Image saved to " + outputFile.getAbsolutePath());

        } catch (MalformedURLException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid URL format");
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "IO error: " + e.getMessage());
        }
    }

    public void init() throws ServletException {
        File dir = new File("/var/www/images/");
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }
}