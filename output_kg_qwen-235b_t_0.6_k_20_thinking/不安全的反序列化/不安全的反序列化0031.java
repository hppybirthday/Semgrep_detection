package com.example.crawler;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

public class VulnerableWebCrawler {
    public static void main(String[] args) {
        VulnerableWebCrawler crawler = new VulnerableWebCrawler();
        String serializedData = crawler.fetchSerializedVisitedUrlFromRemote();
        if (serializedData != null) {
            crawler.processVisitedUrl(serializedData);
        }
    }

    private String fetchSerializedVisitedUrlFromRemote() {
        try {
            URL url = new URL("http://malicious.server/serializedData");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            InputStream is = conn.getInputStream();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[1024];
            while ((nRead = is.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            buffer.flush();
            return Base64.getEncoder().encodeToString(buffer.toByteArray());
        } catch (Exception e) {
            System.err.println("Error fetching serialized data: " + e.getMessage());
            return getDefaultSerializedData();
        }
    }

    private String getDefaultSerializedData() {
        return "rO0ABXNyAC9jb20uZXhhbXBsZS5jcmF3bGVyLlZpc2l0ZWRVcmx8OeZQ0v8mfgIAAUwAA3VybEtAEkxqYXZhL2xsL1N0cmluZzt4cHNyABFqYXZhLnV0aWwuQXJyYXlMaXN0eLdJQ0GjRGV4AgAAeHB3CAAAAEH4AAABAAAAQfgAAABBAQAAAAEAAAA=";
    }

    public void processVisitedUrl(String base64Data) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            VisitedUrl visitedUrl = (VisitedUrl) ois.readObject();
            System.out.println("Visited URL: " + visitedUrl.getUrl());
        } catch (Exception e) {
            System.err.println("Error deserializing object: " + e.getMessage());
        }
    }
}

class VisitedUrl implements Serializable {
    private static final long serialVersionUID = 1L;
    private String url;
    private String timestamp;

    public VisitedUrl(String url, String timestamp) {
        this.url = url;
        this.timestamp = timestamp;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }
}