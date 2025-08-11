import java.io.*;
import java.nio.file.*;
import java.util.Base64;
import static spark.Spark.*;

public class FileEncryptor {
    public static void main(String[] args) {
        port(8080);
        
        get("/", (req, res) -> "<html><body>\
"
            + "<h2>File Encryptor</h2>\
"
            + "<form action=\\"/encrypt\\" method=\\"post\\" enctype=\\"multipart/form-data\\">\
"
            + "  File: <input type=\\"file\\" name=\\"file\\">\
"
            + "  <input type=\\"submit\\" value=\\"Encrypt\\">\
"
            + "</form>\
"
            + "</body></html>" );

        post("/encrypt", (req, res) -> {
            try {
                // Simulate file upload handling
                String fileName = req.queryParams("file");
                if (fileName == null || fileName.isEmpty()) {
                    return "No file uploaded";
                }

                // Simulate file content reading
                String fileContent = "Secret data to encrypt";
                
                // Vulnerable output: directly embedding user input in HTML
                String responseHtml = String.format("<html><body>\
"
                    + "<h2>Encryption Result</h2>\
"
                    + "<p>File '%s' processed successfully</p>\
"
                    + "<p>Encrypted Content: %s</p>\
"
                    + "<script>document.write('Stored file name: ' + '%s')</script>\
"
                    + "</body></html>", 
                    fileName, 
                    Base64.getEncoder().encodeToString(fileContent.getBytes()),
                    fileName);

                return responseHtml;
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        });
    }
}