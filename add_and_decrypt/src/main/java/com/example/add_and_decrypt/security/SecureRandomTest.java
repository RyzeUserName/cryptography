package com.example.add_and_decrypt.security;

import java.security.*;

/**
 * SecureRandom 测试
 * @author Ryze
 * @date 2019-09-23 17:14
 */
public class SecureRandomTest {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        //初始化
        rsa.initialize(512,secureRandom);
        KeyPair keyPair = rsa.generateKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();
    }
}
