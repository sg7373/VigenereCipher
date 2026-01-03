import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class MultiCipherAWT extends Frame {
    private CardLayout cardLayout;
    private Panel loginPanel, signupPanel, mainPanel;
    private Map<String, String> users;
    private TextArea txtInput, txtOutput;
    private TextField txtKey;
    private Choice cipherChoice;
    private String currentCipher;
    
    // Extended ASCII range: printable characters 33-126
    private static final int MIN_CHAR = 33;
    private static final int MAX_CHAR = 126;
    private static final int TOTAL_CHARS = MAX_CHAR - MIN_CHAR + 1;

    public MultiCipherAWT() {
        users = new HashMap<>();
        cardLayout = new CardLayout();
        setLayout(cardLayout);

        createLoginPanel();
        createSignupPanel();
        createMainPanel();

        setTitle("Multi-Cipher Application (Extended ASCII)");
        setSize(600, 400);
        setVisible(true);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent we) {
                System.exit(0);
            }
        });
    }

    private void createLoginPanel() {
        loginPanel = new Panel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);

        Label lblUsername = new Label("Username:");
        TextField txtUsername = new TextField(20);
        Label lblPassword = new Label("Password:");
        TextField txtPassword = new TextField(20);
        txtPassword.setEchoChar('*');
        Button btnLogin = new Button("Login");
        Button btnGoToSignup = new Button("Sign Up");

        gbc.gridx = 0; gbc.gridy = 0;
        loginPanel.add(lblUsername, gbc);
        gbc.gridx = 1;
        loginPanel.add(txtUsername, gbc);
        gbc.gridx = 0; gbc.gridy = 1;
        loginPanel.add(lblPassword, gbc);
        gbc.gridx = 1;
        loginPanel.add(txtPassword, gbc);
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        loginPanel.add(btnLogin, gbc);
        gbc.gridy = 3;
        loginPanel.add(btnGoToSignup, gbc);

        btnLogin.addActionListener(e -> {
            String username = txtUsername.getText();
            String password = txtPassword.getText();
            if (users.containsKey(username) && users.get(username).equals(password)) {
                cardLayout.show(this, "main");
            } else {
                showMessage("Invalid username or password");
            }
        });

        btnGoToSignup.addActionListener(e -> cardLayout.show(this, "signup"));

        add(loginPanel, "login");
    }

    private void createSignupPanel() {
        signupPanel = new Panel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);

        Label lblNewUsername = new Label("New Username:");
        TextField txtNewUsername = new TextField(20);
        Label lblNewPassword = new Label("New Password:");
        TextField txtNewPassword = new TextField(20);
        txtNewPassword.setEchoChar('*');
        Button btnSignup = new Button("Sign Up");
        Button btnBackToLogin = new Button("Back to Login");

        gbc.gridx = 0; gbc.gridy = 0;
        signupPanel.add(lblNewUsername, gbc);
        gbc.gridx = 1;
        signupPanel.add(txtNewUsername, gbc);
        gbc.gridx = 0; gbc.gridy = 1;
        signupPanel.add(lblNewPassword, gbc);
        gbc.gridx = 1;
        signupPanel.add(txtNewPassword, gbc);
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        signupPanel.add(btnSignup, gbc);
        gbc.gridy = 3;
        signupPanel.add(btnBackToLogin, gbc);

        btnSignup.addActionListener(e -> {
            String username = txtNewUsername.getText();
            String password = txtNewPassword.getText();
            if (!users.containsKey(username)) {
                users.put(username, password);
                showMessage("User registered successfully");
                cardLayout.show(this, "login");
            } else {
                showMessage("Username already exists");
            }
        });

        btnBackToLogin.addActionListener(e -> cardLayout.show(this, "login"));

        add(signupPanel, "signup");
    }

    private void createMainPanel() {
        mainPanel = new Panel(new BorderLayout());

        // Navigation bar
        Panel navBar = new Panel();
        cipherChoice = new Choice();
        cipherChoice.add("Vigenère Cipher");
        cipherChoice.add("Caesar Cipher");
        cipherChoice.add("Atbash Cipher");
        currentCipher = "Vigenère Cipher";
        cipherChoice.addItemListener(e -> {
            currentCipher = cipherChoice.getSelectedItem();
            updateKeyVisibility();
        });
        navBar.add(new Label("Select Cipher: "));
        navBar.add(cipherChoice);

        mainPanel.add(navBar, BorderLayout.NORTH);

        // Main content
        Panel contentPanel = new Panel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);

        Label lblInput = new Label("Input:");
        txtInput = new TextArea(10, 40);
        Label lblKey = new Label("Key:");
        txtKey = new TextField(20);
        Label lblOutput = new Label("Output:");
        txtOutput = new TextArea(10, 40);
        txtOutput.setEditable(false);
        Button btnEncrypt = new Button("Encrypt");
        Button btnDecrypt = new Button("Decrypt");
        Button btnSave = new Button("Save to File");
        Button btnOpen = new Button("Open File");
        Button btnLogout = new Button("Logout");

        gbc.gridx = 0; gbc.gridy = 0;
        contentPanel.add(lblInput, gbc);
        gbc.gridx = 1;
        contentPanel.add(txtInput, gbc);
        gbc.gridx = 0; gbc.gridy = 1;
        contentPanel.add(lblKey, gbc);
        gbc.gridx = 1;
        contentPanel.add(txtKey, gbc);
        gbc.gridx = 0; gbc.gridy = 2;
        contentPanel.add(lblOutput, gbc);
        gbc.gridx = 1;
        contentPanel.add(txtOutput, gbc);

        Panel buttonPanel = new Panel();
        buttonPanel.add(btnEncrypt);
        buttonPanel.add(btnDecrypt);
        buttonPanel.add(btnSave);
        buttonPanel.add(btnOpen);
        buttonPanel.add(btnLogout);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        contentPanel.add(buttonPanel, gbc);

        mainPanel.add(contentPanel, BorderLayout.CENTER);

        btnEncrypt.addActionListener(e -> performCipherOperation(true));
        btnDecrypt.addActionListener(e -> performCipherOperation(false));
        btnSave.addActionListener(e -> saveToFile());
        btnOpen.addActionListener(e -> openFile());
        btnLogout.addActionListener(e -> {
            txtInput.setText("");
            txtKey.setText("");
            txtOutput.setText("");
            cardLayout.show(this, "login");
        });

        add(mainPanel, "main");
    }

    private void updateKeyVisibility() {
        txtKey.setVisible(currentCipher.equals("Vigenère Cipher") || currentCipher.equals("Caesar Cipher"));
    }

    private void performCipherOperation(boolean encrypt) {
        String input = txtInput.getText();
        String key = txtKey.getText().toUpperCase();

        if (currentCipher.equals("Vigenère Cipher") || currentCipher.equals("Caesar Cipher")) {
            if (key.isEmpty()) {
                showMessage("Key cannot be empty for " + currentCipher);
                return;
            }
        }

        String result = "";
        switch (currentCipher) {
            case "Vigenère Cipher":
                result = encrypt ? encryptVigenere(input, key) : decryptVigenere(input, key);
                break;
            case "Caesar Cipher":
                try {
                    int shift = Integer.parseInt(key);
                    result = encrypt ? encryptCaesar(input, shift) : decryptCaesar(input, shift);
                } catch (NumberFormatException e) {
                    showMessage("Invalid shift value for Caesar cipher");
                    return;
                }
                break;
            case "Atbash Cipher":
                result = atbashCipher(input);
                break;
        }
        txtOutput.setText(result);
    }

    private String encryptVigenere(String plaintext, String key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0, j = 0; i < plaintext.length(); i++) {
            char c = plaintext.charAt(i);
            if (isPrintableASCII(c)) {
                char keyChar = key.charAt(j);
                char encryptedChar = (char) ((c + keyChar - 2 * MIN_CHAR) % TOTAL_CHARS + MIN_CHAR);
                result.append(encryptedChar);
                j = (j + 1) % key.length();
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private String decryptVigenere(String ciphertext, String key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0, j = 0; i < ciphertext.length(); i++) {
            char c = ciphertext.charAt(i);
            if (isPrintableASCII(c)) {
                char keyChar = key.charAt(j);
                char decryptedChar = (char) ((c - keyChar + TOTAL_CHARS) % TOTAL_CHARS + MIN_CHAR);
                result.append(decryptedChar);
                j = (j + 1) % key.length();
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private String encryptCaesar(String plaintext, int shift) {
        StringBuilder result = new StringBuilder();
        for (char c : plaintext.toCharArray()) {
            if (isPrintableASCII(c)) {
                char shiftedChar = (char) ((c - MIN_CHAR + shift) % TOTAL_CHARS + MIN_CHAR);
                result.append(shiftedChar);
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private String decryptCaesar(String ciphertext, int shift) {
        return encryptCaesar(ciphertext, TOTAL_CHARS - shift);
    }

    private String atbashCipher(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (isPrintableASCII(c)) {
                char atbashChar = (char) (MAX_CHAR - (c - MIN_CHAR));
                result.append(atbashChar);
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private boolean isPrintableASCII(char c) {
        return c >= MIN_CHAR && c <= MAX_CHAR;
    }

    private void saveToFile() {
        FileDialog fd = new FileDialog(this, "Save File", FileDialog.SAVE);
        fd.setVisible(true);
        String filename = fd.getFile();
        if (filename != null) {
            try (PrintWriter out = new PrintWriter(new FileWriter(fd.getDirectory() + filename))) {
                out.println(txtOutput.getText());
                showMessage("File saved successfully");
            } catch (IOException e) {
                showMessage("Error saving file: " + e.getMessage());
            }
        }
    }

    private void openFile() {
        FileDialog fd = new FileDialog(this, "Open File", FileDialog.LOAD);
        fd.setVisible(true);
        String filename = fd.getFile();
        if (filename != null) {
            try (BufferedReader br = new BufferedReader(new FileReader(fd.getDirectory() + filename))) {
                StringBuilder content = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    content.append(line).append("\n");
                }
                txtInput.setText(content.toString());
                showMessage("File opened successfully");
            } catch (IOException e) {
                showMessage("Error opening file: " + e.getMessage());
            }
        }
    }

    private void showMessage(String message) {
        Dialog dialog = new Dialog(this, "Message", true);
        dialog.setLayout(new FlowLayout());
        dialog.add(new Label(message));
        Button btnOK = new Button("OK");
        btnOK.addActionListener(e -> dialog.dispose());
        dialog.add(btnOK);
        dialog.setSize(250, 100);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    public static void main(String[] args) {
        new MultiCipherAWT();
    }
}
