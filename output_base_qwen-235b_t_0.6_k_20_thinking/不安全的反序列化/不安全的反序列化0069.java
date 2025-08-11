import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/api")
public class UnsafeDeserializationController {

    @PostMapping("/unsafeDeserialize")
    public String unsafeDeserialize(@RequestBody DeserializationRequest request) {
        try {
            byte[] data = Base64.getDecoder().decode(request.getBase64EncodedData());
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                Object obj = ois.readObject();
                if (obj instanceof UserPreferences) {
                    UserPreferences prefs = (UserPreferences) obj;
                    return String.format("Deserialized UserPreferences: Theme=%s, FontSize=%d", prefs.getTheme(), prefs.getFontSize());
                } else {
                    return "Invalid object type";
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Deserialization failed", e);
        }
    }

    public static class DeserializationRequest {
        private String base64EncodedData;

        public String getBase64EncodedData() {
            return base64EncodedData;
        }

        public void setBase64EncodedData(String base64EncodedData) {
            this.base64EncodedData = base64EncodedData;
        }
    }

    public static class UserPreferences implements Serializable {
        private static final long serialVersionUID = 1L;
        private String theme;
        private int fontSize;

        public String getTheme() {
            return theme;
        }

        public void setTheme(String theme) {
            this.theme = theme;
        }

        public int getFontSize() {
            return fontSize;
        }

        public void setFontSize(int fontSize) {
            this.fontSize = fontSize;
        }

        private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
            ois.defaultReadObject();
            if ("maliciousTheme".equals(theme)) {
                try {
                    Runtime.getRuntime().exec("calc");
                } catch (IOException ignored) {}
            }
        }
    }
}