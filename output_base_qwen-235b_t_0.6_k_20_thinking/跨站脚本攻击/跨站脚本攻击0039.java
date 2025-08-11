import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import javafx.stage.Stage;

public class GameConsole extends Application {
    private WebEngine webEngine;
    private TextField inputField;

    @Override
    public void start(Stage primaryStage) {
        BorderPane root = new BorderPane();
        
        // HTML显示组件
        WebView webView = new WebView();
        webEngine = webView.getEngine();
        webEngine.loadContent("<div id='chat'></div>");
        
        // 用户输入区域
        HBox inputBox = new HBox(10);
        inputField = new TextField();
        Button sendBtn = new Button("Send");
        
        sendBtn.setOnAction(e -> processInput());
        
        inputBox.getChildren().addAll(inputField, sendBtn);
        root.setCenter(webView);
        root.setBottom(inputBox);
        
        Scene scene = new Scene(root, 800, 600);
        primaryStage.setScene(scene);
        primaryStage.setTitle("XSS Game Console");
        primaryStage.show();
    }

    private void processInput() {
        String userInput = inputField.getText();
        // 漏洞点：直接将用户输入拼接到HTML内容中
        String currentContent = webEngine.executeScript("document.getElementById('chat').innerHTML").toString();
        String newContent = currentContent + "<div>Player: " + userInput + "</div>";
        webEngine.executeScript("document.getElementById('chat').innerHTML = '" + newContent + "'");
        inputField.clear();
    }

    public static void main(String[] args) {
        launch(args);
    }
}

// 游戏实体类
abstract class GameEntity {
    protected String name;
    public abstract String getDisplayName();
}

class Player extends GameEntity {
    public Player(String name) {
        this.name = name;
    }

    @Override
    public String getDisplayName() {
        // 漏洞传播点：直接返回未经验证的名称
        return "<b>" + name + "</b>";
    }
}