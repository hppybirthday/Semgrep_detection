import java.io.*;
import java.nio.file.*;
import javafx.application.*;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.image.*;
import javafx.scene.layout.*;
import javafx.stage.*;

public class GameResourceLoader extends Application {
    private static final String BASE_PATH = "resources/images/";
    
    @Override
    public void start(Stage primaryStage) {
        VBox root = new VBox(10);
        TextField input = new TextField("Enter image name");
        ImageView imageView = new ImageView();
        
        Button loadBtn = new Button("Load Image");
        loadBtn.setOnAction(e -> {
            String userInput = input.getText();
            try {
                // 漏洞点：直接拼接用户输入
                String safePath = BASE_PATH + userInput;
                File file = new File(safePath);
                
                if (file.exists()) {
                    Image image = new Image(new FileInputStream(file));
                    imageView.setImage(image);
                } else {
                    showAlert("File not found: " + userInput);
                }
            } catch (Exception ex) {
                showAlert("Error loading image: " + ex.getMessage());
            }
        });
        
        root.getChildren().addAll(input, loadBtn, imageView);
        Scene scene = new Scene(root, 400, 300);
        primaryStage.setScene(scene);
        primaryStage.setTitle("Game Resource Loader");
        primaryStage.show();
    }
    
    private void showAlert(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setContentText(message);
        alert.showAndWait();
    }
    
    public static void main(String[] args) {
        launch(args);
    }
}