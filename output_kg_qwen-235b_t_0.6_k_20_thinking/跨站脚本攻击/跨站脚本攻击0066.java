import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.text.*;
import javax.swing.text.html.*;

public class GameChatApp {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new GameChatFrame().setVisible(true));
    }
}

class GameChatFrame extends JFrame {
    private ChatPanel chatPanel;

    public GameChatFrame() {
        setTitle("Game Chat - Vulnerable Version");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        
        chatPanel = new ChatPanel();
        add(chatPanel, BorderLayout.CENTER);
    }
}

class ChatPanel extends JPanel {
    private JEditorPane chatArea;
    private JTextField inputField;
    private StyledDocument doc;

    public ChatPanel() {
        setLayout(new BorderLayout(5, 5));
        
        // Chat display area
        chatArea = new JEditorPane();
        chatArea.setContentType("text/html");
        chatArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(chatArea);
        
        // Input components
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputField = new JTextField();
        JButton sendButton = new JButton("Send");
        
        // Vulnerable code: Direct user input concatenation
        sendButton.addActionListener(e -> addMessage(inputField.getText()));
        inputField.addActionListener(e -> addMessage(inputField.getText()));
        
        inputPanel.add(inputField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);
        
        add(scrollPane, BorderLayout.CENTER);
        add(inputPanel, BorderLayout.SOUTH);
        
        doc = (StyledDocument) chatArea.getDocument();
        try {
            doc.insertString(doc.getLength(), "<html><body style='font-family:Arial'>", null);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void addMessage(String message) {
        if (message.trim().isEmpty()) return;
        
        try {
            // Vulnerability: No HTML escaping of user input
            String htmlContent = String.format("<p style='color:#1a73e8'>Player: %s</p>", message);
            doc.insertString(doc.getLength(), htmlContent, null);
            inputField.setText("");
            chatArea.setCaretPosition(doc.getLength());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}