package com.example.add_and_decrypt.crypto;

import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * CipherInputStream 测试类
 * @author Ryze
 * @date 2019-09-25 16:43
 */
public class CipherInputStreamTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        //des 生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        //初始化
        Cipher cipher = Cipher.getInstance("DES");
        //解密模式
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        //初始化流
        CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(new File("secret")), cipher);
        DataInputStream dataInputStream = new DataInputStream(cipherInputStream);
        //读出解密的数据
        String s = dataInputStream.readUTF();
        dataInputStream.close();
        cipherInputStream.close();
    }
}
