package com.example.add_and_decrypt.security;

import java.security.*;

/**
 * KeyPairGenerator 测试
 * @author Ryze
 * @date 2019-09-23 16:51
 */
public class KeyPairGeneratorTest {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyPairGenerator ras = KeyPairGenerator.getInstance("RSA");
        //初始化
        ras.initialize(512);
        KeyPair keyPair = ras.generateKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();
    }
}
