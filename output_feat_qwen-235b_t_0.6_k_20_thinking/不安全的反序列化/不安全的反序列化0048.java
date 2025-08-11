import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;

public class FileCrypt {
    static class Config {
        String algo = "AES";
        String key = "default_key";
        boolean compress = true;
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java FileCrypt <encrypt|decrypt> <filepath>");
            return;
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            Config config = mapper.readValue(new File("config.json"), Config.class);
            
            if (args[0].equals("decrypt")) {
                decryptFile(args[1], config);
            } else {
                encryptFile(args[1], config);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    static void decryptFile(String path, Config config) {
        System.out.println(String.format("Decrypting %s with %s using key %s", 
            path, config.algo, config.key));
        // Actual decryption logic would be here
    }

    static void encryptFile(String path, Config config) {
        System.out.println(String.format("Encrypting %s with %s using key %s", 
            path, config.algo, config.key));
        // Actual encryption logic would be here
    }

    // Simulated vulnerable update method
    void updateAuthProviderEnabled(String jsonInput) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        // VULNERABLE: Untrusted deserialization
        mapper.readValue(jsonInput, Config.class);
    }
}