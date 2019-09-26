package com.example.add_and_decrypt.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * DESKeySpec 测试
 * @author Ryze
 * @date 2019-09-26 9:48
 */
public class DESKeySpecTest {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        //将DES 换称 DESede （三重DES）大致相同
        KeyGenerator generator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = generator.generateKey();
        byte[] encoded = secretKey.getEncoded();

        //通过SecretKeySpec 生成key
        SecretKeySpec des = new SecretKeySpec(encoded, "DES");
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey1 = secretKeyFactory.generateSecret(des);
        System.out.println(secretKey.equals(secretKey1));

        //DESKeySpec 生成key
        DESKeySpec desKeySpec = new DESKeySpec(encoded);
        SecretKey secretKey2 = secretKeyFactory.generateSecret(desKeySpec);
        System.out.println(secretKey.equals(secretKey2));

    }
}
