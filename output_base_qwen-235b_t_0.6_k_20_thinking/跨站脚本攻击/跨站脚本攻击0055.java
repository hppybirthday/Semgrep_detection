import java.lang.reflect.Method;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import javafx.stage.Stage;

public class GameXSSDemo extends Application {
    private WebEngine engine;
    private TextField inputField;

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        try {
            Class<?> handlerClass = createDynamicHandler();
            Object handlerInstance = handlerClass.getDeclaredConstructor().newInstance();
            
            inputField = new TextField();
            Button submitBtn = new Button("Submit");
            WebView webView = new WebView();
            engine = webView.getEngine();
            
            Method method = handlerClass.getMethod("handleInput", String.class);
            submitBtn.setOnAction(e -> {
                try {
                    String userInput = inputField.getText();
                    String response = (String) method.invoke(handlerInstance, userInput);
                    engine.loadContent(response);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            });
            
            VBox root = new VBox(10, inputField, submitBtn, webView);
            Scene scene = new Scene(root, 400, 300);
            primaryStage.setScene(scene);
            primaryStage.setTitle("Game Profile Viewer");
            primaryStage.show();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Class<?> createDynamicHandler() throws Exception {
        String className = "DynamicXSSHandler";
        String code = "public class " + className + " {"
            + "    public String handleInput(String input) {"
            + "        return \\"<html><body><h1>Welcome, \\" + input + \\"</h1></body></html>\\";"
            + "    }"
            + "}";
        
        // Simulated dynamic class generation
        byte[] classBytes = compileJavaToBytecode(className, code);
        return defineClass(className, classBytes);
    }

    private byte[] compileJavaToBytecode(String className, String code) {
        // Simplified stub - actual implementation would use JavaCompiler API
        return new byte[0];
    }

    private Class<?> defineClass(String name, byte[] b) {
        return defineClass(name, b, 0, b.length);
    }

    // Vulnerable method that allows XSS
    public String generateProfileHTML(String username) {
        return "<html><body><h1>Welcome, " + username + "</h1></body></html>";
    }
}