package com.example.add_and_decrypt.crypto;

import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * CipherOutputStream 测试类
 * @author Ryze
 * @date 2019-09-25 16:43
 */
public class CipherOutputStreamTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        //des 生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        //初始化
        Cipher cipher = Cipher.getInstance("DES");
        //加密模式
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //初始化流
        CipherOutputStream cipherInputStream = new CipherOutputStream(new FileOutputStream(new File("secret")), cipher);
        DataOutputStream dataInputStream = new DataOutputStream(cipherInputStream);
        //写入加密的数据
        dataInputStream.writeUTF("data");
        dataInputStream.close();
        cipherInputStream.close();
    }
}
