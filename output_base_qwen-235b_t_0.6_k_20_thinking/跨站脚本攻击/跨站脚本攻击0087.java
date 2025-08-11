import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.scene.web.WebView;
import javafx.stage.Stage;
import java.util.ArrayList;
import java.util.List;

// 领域模型
class ChatMessage {
    private String content;
    public ChatMessage(String content) {
        this.content = content;
    }
    public String getContent() {
        return content;
    }
}

// 仓储接口
class ChatRepository {
    private List<ChatMessage> messages = new ArrayList<>();
    public void save(ChatMessage message) {
        messages.add(message);
    }
    public List<ChatMessage> getAll() {
        return messages;
    }
}

// 应用服务
class ChatService {
    private ChatRepository repository = new ChatRepository();
    public void sendMessage(String content) {
        repository.save(new ChatMessage(content));
    }
    public List<ChatMessage> getChatHistory() {
        return repository.getAll();
    }
}

// UI组件
class ChatWindow extends VBox {
    private WebView chatView = new WebView();
    private ChatService chatService = new ChatService();

    public ChatWindow() {
        TextField input = new TextField();
        Button send = new Button("Send");
        
        send.setOnAction(e -> {
            String message = input.getText();
            chatService.sendMessage(message);
            refreshChat();
            input.clear();
        });
        
        this.getChildren().addAll(chatView, input, send);
    }
    
    private void refreshChat() {
        StringBuilder html = new StringBuilder("<html><body>");
        for (ChatMessage msg : chatService.getChatHistory()) {
            // 危险操作：直接拼接用户输入内容
            html.append(String.format("<div>%s</div>", msg.getContent()));
        }
        html.append("</body></html>");
        chatView.getEngine().loadContent(html.toString());
    }
}

// 主程序
public class GameChatApp extends Application {
    @Override
    public void start(Stage primaryStage) {
        Scene scene = new Scene(new ChatWindow(), 400, 300);
        primaryStage.setScene(scene);
        primaryStage.setTitle("Game Chat");
        primaryStage.show();
    }
    
    public static void main(String[] args) {
        launch(args);
    }
}