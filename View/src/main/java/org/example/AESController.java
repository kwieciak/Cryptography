package org.example;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Alert;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
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
    private int keyLength = 0;

    private AES aes = new AES(keyLength);

    @FXML
    private TextArea keyInput;

    @FXML
    private TextArea unecryptedText;

    @FXML
    private TextArea ecryptedText;

    @FXML
    private ChoiceBox<Integer> keyLengthChoice;


    private Integer[] keyLengths = {128, 192, 256};

    private byte[] fileContent;
    //String path;
    boolean isFileloaded = false;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        keyLengthChoice.getItems().addAll(keyLengths);
        keyLengthChoice.setOnAction(this::getKeyLength);
        ecryptedText.setEditable(false);
    }

    private void getKeyLength(javafx.event.ActionEvent actionEvent) {
        keyLength = keyLengthChoice.getValue();
    }

    @FXML
    protected void keyGenerator() {
        if (this.keyLength == 0) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setContentText("The key length has been not selected");
            alert.show();
        }
        aes = new AES(keyLength);
        aes.generateKey();
        byte[] key = aes.getKey();
        StringBuilder str = new StringBuilder(new String());
        for (int i = 0; i < keyLength / 8; i++) {
            str.append((char) key[i]);
        }
        keyInput.setText(str.toString());
    }


    @FXML
    protected void loadFile(ActionEvent event) throws IOException {
        File file = fileChooser.showOpenDialog(new Stage());
        if (file != null) {
            String path = file.getPath();
            fileContent = Files.readAllBytes(Paths.get(path));
            isFileloaded = true;
        }
    }

    @FXML
    protected void encryptButton() throws Exception {
        if (isFileloaded == true) {
            fileContent = aes.encode(fileContent);
        } else if (unecryptedText != null) {
            fileContent = unecryptedText.getText().getBytes();
            fileContent = aes.encode(fileContent);
            byte[] result = Base64.getEncoder().encode(fileContent);
            String str = new String(result);
            ecryptedText.setText(str);
        }
    }

    @FXML
    protected void unecryptButton() {
        if (isFileloaded == true) {
            fileContent = aes.decode(fileContent);
        }
    }


    @FXML
    protected void saveFile(ActionEvent event) throws IOException {
        File file = fileChooser.showSaveDialog(new Stage());
        if (file != null) {
            String path = file.getPath();
            OutputStream outputStream = new FileOutputStream(path);
            outputStream.write(fileContent, 0, fileContent.length);
            outputStream.close();
            fileContent = null;
            isFileloaded = false;
            unecryptedText.setText(null);
            ecryptedText.setText(null);
        }
    }

    @FXML
    protected void saveKey(ActionEvent event) throws IOException {
        File file = fileChooser.showSaveDialog(new Stage());
        if (file != null) {
                String path = file.getPath();
                OutputStream outputStream = new FileOutputStream(path);
                outputStream.write(keyInput.getText().getBytes(), 0, keyInput.getText().getBytes().length);
                outputStream.close();
        }
    }

  /*  @FXML
    protected void loadKey(ActionEvent event) throws IOException {
        File file = fileChooser.showOpenDialog(new Stage());
        if (file != null) {
            String path = file.getPath();
            byte[] keyHelper = Files.readAllBytes(Paths.get(path));
            aes.setKey(keyHelper);
            byte[] result = Base64.getEncoder().encode(keyHelper);
            String str = new String(result);
            keyInput.setText(str);
        }
    } */
}
