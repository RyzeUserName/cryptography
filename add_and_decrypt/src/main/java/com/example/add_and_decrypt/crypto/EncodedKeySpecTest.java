package com.example.add_and_decrypt.crypto;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * EncodedKeySpec  测试
 * @author Ryze
 * @date 2019-09-25 17:56
 */
public class EncodedKeySpecTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");
        dsa.initialize(512);
        KeyPair keyPair = dsa.genKeyPair();
        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();
        byte[] pub = aPublic.getEncoded();
        byte[] pri = aPrivate.getEncoded();
        //公钥  私钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pub);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(pri);
        KeyFactory factory = KeyFactory.getInstance("DSA");
        PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);
        PrivateKey privateKey = factory.generatePrivate(pkcs8EncodedKeySpec);
        System.out.println(publicKey.equals(aPublic));
        System.out.println(privateKey.equals(aPrivate));
    }
}
