import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import javafx.stage.Stage;

public class GameCategoryManager extends Application {
    private Category currentCategory = new Category();
    private WebEngine webEngine;

    @Override
    public void start(Stage primaryStage) {
        // 创建UI组件
        TextField titleField = new TextField();
        TextArea descArea = new TextArea();
        Button submitBtn = new Button("Create Category");
        WebView previewView = new WebView();
        webEngine = previewView.getEngine();

        // 表单提交逻辑
        submitBtn.setOnAction(e -> {
            currentCategory.setTitle(titleField.getText());
            currentCategory.setDescription(descArea.getText());
            updatePreview();
        });

        // UI布局
        VBox inputPanel = new VBox(10, 
            new Label("Category Title:"), titleField,
            new Label("Description:"), descArea,
            submitBtn
        );

        SplitPane root = new SplitPane(inputPanel, previewView);
        Scene scene = new Scene(root, 800, 600);
        primaryStage.setScene(scene);
        primaryStage.setTitle("Game Category Manager");
        primaryStage.show();
    }

    private void updatePreview() {
        // 漏洞点：直接拼接用户输入到HTML内容中
        String htmlContent = "<html><body style='font-family:Arial'>"
                          + "<h1>Preview: " + currentCategory.getTitle() + "</h1>"
                          + "<p>" + currentCategory.getDescription() + "</p>"
                          + "<div style='margin-top:20px'>Last updated: " 
                          + new java.util.Date() + "</div>"
                          + "</body></html>";
        webEngine.loadContent(htmlContent);
    }

    // 游戏分类模型类
    static class Category {
        private String title;
        private String description;

        public String getTitle() { return title; }
        public void setTitle(String title) { this.title = title; }
        
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
    }

    public static void main(String[] args) {
        launch(args);
    }
}