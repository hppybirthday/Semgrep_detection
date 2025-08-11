import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

public class GameChatApp extends JFrame {
    private final JTextArea inputArea = new JTextArea(3, 20);
    private final JEditorPane displayPane = new JEditorPane("text/html", "");
    private final List<String> chatHistory = new ArrayList<>();

    public GameChatApp() {
        setTitle("XSS Game Chat");
        setSize(600, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        initUI();
    }

    private void initUI() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // 输入面板
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.add(new JScrollPane(inputArea), BorderLayout.CENTER);
        JButton sendBtn = new JButton("Send");
        sendBtn.addActionListener(this::handleSend);
        inputPanel.add(sendBtn, BorderLayout.EAST);
        
        // 显示面板
        displayPane.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(displayPane);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(inputPanel, BorderLayout.SOUTH);
        add(panel);
    }

    private void handleSend(ActionEvent e) {
        String message = inputArea.getText().trim();
        if (!message.isEmpty()) {
            chatHistory.add(message);
            updateDisplay();
            inputArea.setText("");
        }
    }

    private void updateDisplay() {
        StringBuilder html = new StringBuilder("<html><body style='font-family: Arial;'>");
        for (String msg : chatHistory) {
            // 漏洞点：直接拼接用户输入到HTML内容中
            html.append("<p style='margin: 5px 0;'>").append(msg).append("</p>");
        }
        html.append("</body></html>");
        
        displayPane.setText(html.toString());
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new GameChatApp().setVisible(true);
        });
    }
}