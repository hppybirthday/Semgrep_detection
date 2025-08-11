import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

public class ChatMessageHandler {
    
    // Function to validate and process image URLs from chat messages
    public static Function<String, String> processImageMessage = (userInput) -> {
        try {
            // Vulnerable: Directly using user input to construct URL
            URL imageUrl = new URL(userInput);
            HttpURLConnection connection = (HttpURLConnection) imageUrl.openConnection();
            connection.setRequestMethod("GET");
            connection.connect();
            
            // Check if it's an image
            if (connection.getContentType() != null && 
                connection.getContentType().startsWith("image/")) {
                
                // Process image metadata
                int fileSize = connection.getContentLength();
                int width = connection.getHeaderFieldInt("Image-Width", -1);
                int height = connection.getHeaderFieldInt("Image-Height", -1);
                
                return String.format("Valid image: %dKB, %dx%d", 
                    fileSize/1024, width, height);
            }
            return "Not an image URL";
            
        } catch (Exception e) {
            return "Error processing URL: " + e.getMessage();
        }
    };
    
    // Simulated chat message processing
    public static void handleIncomingMessage(String messageContent) {
        // Check if message contains a potential image URL
        if (messageContent.startsWith("[image]") && messageContent.endsWith("[/image]")) {
            String imageUrl = messageContent.substring(7, messageContent.length()-8);
            
            // Process image URL in vulnerable way
            String result = processImageMessage.apply(imageUrl);
            System.out.println("[SERVER] Image analysis: " + result);
            
            // In a real app this would be sent back to client
            if (result.contains("Error")) {
                System.out.println("[SERVER] Warning: Invalid image URL detected");
            }
        } else {
            System.out.println("[SERVER] Regular message: " + messageContent);
        }
    }
    
    public static void main(String[] args) {
        System.out.println("=== Chat Application Server ===");
        System.out.println("Enter chat messages (use [image]url[/image] format)");
        
        // Simulating server processing loop
        String[] testMessages = {
            "Hello world!",
            "[image]http://example.com/normal-image.png[/image]",
            "[image]http://localhost:8080/internal-secret-api[/image]",
            "[image]file:///etc/passwd[/image]",
            "[image]https://api.internal-service.com/admin/data[/image]"
        };
        
        for (String message : testMessages) {
            System.out.println("\
Received message: " + message);
            handleIncomingMessage(message);
        }
    }
}