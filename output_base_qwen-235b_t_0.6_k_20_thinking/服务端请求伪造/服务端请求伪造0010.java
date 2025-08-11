import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import com.opencsv.CSVReader;

public class DataCleaner {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java DataCleaner <csvFilePath>");
            return;
        }
        
        String csvFilePath = args[0];
        try (CSVReader reader = new CSVReader(new FileReader(csvFilePath))) {
            List<String[]> data = reader.readAll();
            
            // Assume first row is header
            boolean headerSkipped = false;
            
            for (String[] row : data) {
                if (!headerSkipped) {
                    headerSkipped = true;
                    continue;
                }
                
                // Process URL from CSV column 2
                String url = row[2];
                String content = fetchRemoteContent(url);
                
                // Basic cleaning
                String cleaned = content.replaceAll("\\s+", " ").trim();
                
                // Save cleaned content back to row
                row[2] = cleaned;
                // In real app would write to output file
                System.out.println("Cleaned content: " + cleaned.substring(0, Math.min(50, cleaned.length())) + "...");
            }
        } catch (Exception e) {
            System.err.println("Error processing CSV: " + e.getMessage());
        }
    }

    private static String fetchRemoteContent(String url) throws IOException {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setRequestMethod("GET");
            
            // Vulnerable: No URL validation
            int responseCode = connection.getResponseCode();
            if (responseCode != 200) {
                throw new IOException("HTTP error code: " + responseCode);
            }
            
            BufferedReader in = new BufferedReader(
                new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            
            return content.toString();
        } catch (Exception e) {
            throw new IOException("Failed to fetch remote content: " + e.getMessage(), e);
        }
    }
}