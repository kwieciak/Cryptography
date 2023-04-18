package org.example;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.ResourceBundle;
import java.util.Scanner;

public class AESController implements Initializable {

    private FileChooser fileChooser = new FileChooser();
    private int keyLength;

    private AES aes = new AES(keyLength);

    @FXML
    private TextArea keyInput;

    @FXML
    private TextField keyFromFile;

    @FXML
    private TextField keyToSave;

    @FXML
    private TextArea unecryptedText;

    @FXML
    private TextArea ecryptedText;

    @FXML
    private ChoiceBox<Integer> keyLengthChoice;

    @FXML
    private TextArea unecryptedFile;


    private Integer[] keyLengths = {128, 192, 256};

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        keyLengthChoice.getItems().addAll(keyLengths);
        keyLengthChoice.setOnAction(this::getKeyLength);
    }

    private void getKeyLength(javafx.event.ActionEvent actionEvent) {
        keyLength = keyLengthChoice.getValue();
    }

    @FXML
    protected void keyGenerator(){
        aes = new AES(keyLength);
        aes.generateKey();
        byte [] key = aes.getKey();
        StringBuilder str = new StringBuilder(new String());
        for(int i = 0; i<keyLength/8; i++){
            str.append((char)key[i]);
        }
        keyInput.setText(str.toString());
    }

    @FXML
    protected void encryptButton(){
        if(unecryptedText != null) {
            byte[] text = unecryptedText.getText().getBytes();
            text = aes.encode(text);
            byte[] result = Base64.getEncoder().encode(text);
            String str = new String(result);
            ecryptedText.setText(str);
        }
        else if(fileContent != null){
            fileContent = aes.encode(fileContent);
        }
    }

    @FXML
    protected void unecryptButton(){
        if(ecryptedText != null ) {
            byte[] text = ecryptedText.getText().getBytes();
            byte[] result = Base64.getDecoder().decode(text);
            result = aes.decode(result);
            String str = new String(result);
            unecryptedText.setText(str);
        }
        else if(fileContent != null){
            fileContent = aes.decode(fileContent);
        }
    }

    @FXML
    protected void loadKeyFromFile(ActionEvent event) {
        File file = fileChooser.showOpenDialog(new Stage());
        try {
            Scanner scanner = new Scanner(file);
            while(scanner.hasNext()) {
                keyFromFile.appendText(scanner.nextLine());
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        aes.setKey(keyFromFile.getText().getBytes());
    }

    private byte[] fileContent;
    String path;

    @FXML
    protected void loadUnecryptedAndEcryptedFile(ActionEvent event) throws IOException {
        File file = fileChooser.showOpenDialog(new Stage());
        if(file != null){
            path = file.getPath();
            fileContent = Files.readAllBytes(Paths.get(path));
        }
    }

    // @FXML
    // protected void saveUnecryptedAndEcryptedFile(ActionEvent){
    // FileOutputStream fileOutputStream = new FileOutputStream(fileContent);
    // }

    @FXML
    protected void loadUnecryptedText(ActionEvent event) {
        File file = fileChooser.showOpenDialog(new Stage());
        try {
            Scanner scanner = new Scanner(file);
            while(scanner.hasNext()) {
                unecryptedText.appendText(scanner.nextLine());
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @FXML
    protected void loadEcryptedText(ActionEvent event) {
        File file = fileChooser.showOpenDialog(new Stage());
        try {
            Scanner scanner = new Scanner(file);
            while(scanner.hasNext()) {
                ecryptedText.appendText(scanner.nextLine());
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @FXML
    protected void saveEcrptedText(ActionEvent event) {
        File file = fileChooser.showSaveDialog(new Stage());
        if (file != null) {
            try {
                PrintWriter printWriter = new PrintWriter(file);
                printWriter.write(ecryptedText.getText());
                printWriter.close();
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @FXML
    protected void saveUnecrpytedText(ActionEvent event) {
        File file = fileChooser.showSaveDialog(new Stage());
        if (file != null) {
            try {
                PrintWriter printWriter = new PrintWriter(file);
                printWriter.write(unecryptedText.getText());
                printWriter.close();
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @FXML
    protected void saveKey(ActionEvent event) {
        File file = fileChooser.showSaveDialog(new Stage());
        if (file != null) {
            try {
                PrintWriter printWriter = new PrintWriter(file);
                printWriter.write(keyToSave.getText());
                printWriter.close();
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
    }
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
