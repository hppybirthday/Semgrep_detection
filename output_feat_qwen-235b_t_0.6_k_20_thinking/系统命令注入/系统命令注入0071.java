import java.io.*;
import java.util.*;
import javafx.application.*;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;

public class GameLauncher extends Application {
    @Override
    public void start(Stage primaryStage) {
        TextField levelInput = new TextField();
        Button launchBtn = new Button("Launch Level");
        
        launchBtn.setOnAction(e -> {
            String levelName = levelInput.getText();
            try {
                // 模拟游戏启动器调用外部脚本处理关卡文件
                String cmd = "python process_level.py " + levelName;
                Process process = Runtime.getRuntime().exec(cmd);
                
                // 读取脚本输出流
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
                
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        });
        
        VBox root = new VBox(10, new Label("Enter Level Name:"), levelInput, launchBtn);
        Scene scene = new Scene(root, 300, 200);
        primaryStage.setScene(scene);
        primaryStage.setTitle("Game Level Launcher");
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
// 模拟process_level.py内容：
// import sys
// print(f"Processing level: {sys.argv[1]}")
// with open(f"levels/{sys.argv[1]}", 'r') as f:
//     print(f.read())