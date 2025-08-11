import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.util.Timer;
import java.util.TimerTask;
import java.io.*;

public class GameLauncher extends JFrame {
    private JTextField cmdInput = new JTextField(30);
    private JTextArea outputArea = new JTextArea(10, 30);
    private ProcessBuilder pb;

    public GameLauncher() {
        super("Game Asset Manager");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new FlowLayout());
        
        add(new JLabel("Enter asset path:"));
        add(cmdInput);
        add(new JScrollPane(outputArea));
        JButton execBtn = new JButton("Process Asset");
        
        execBtn.addActionListener((e) -> {
            String userInput = cmdInput.getText();
            try {
                pb = new ProcessBuilder("magic-pdf", userInput);
                Process process = pb.start();
                InputStream is = process.getInputStream();
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(is));
                String line;
                while ((line = reader.readLine()) != null) {
                    outputArea.append(line + "\
");
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        });
        
        add(execBtn);
        pack();
        setVisible(true);
        
        // 模拟定时任务触发
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (!cmdInput.getText().isEmpty()) {
                    try {
                        // 使用系统shell执行命令
                        pb = new ProcessBuilder("/bin/sh", "-c", "magic-pdf " + cmdInput.getText());
                        Process process = pb.start();
                        // 忽略错误流处理
                    } catch (Exception ignored) {}
                }
            }
        }, 5000, 10000);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new GameLauncher());
    }
}