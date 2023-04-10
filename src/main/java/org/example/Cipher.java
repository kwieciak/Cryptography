package org.example;

public interface Cipher {
    byte[] encipher(byte[] data);
    byte[] decipher(byte[] data);
}
