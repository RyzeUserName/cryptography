package com.example.add_and_decrypt.security;

import java.io.IOException;
import java.security.*;

/**
 * SignedObject 测试
 * @author Ryze
 * @date 2019-09-23 17:43
 */
@SuppressWarnings("all")
public class SignedObjectTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        //数据
        byte[] datas = "data".getBytes();

        //生成公私钥
        KeyPairGenerator ras = KeyPairGenerator.getInstance("RSA");
        ras.initialize(512);
        KeyPair keyPair = ras.generateKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();

        //签名
        Signature sha256withRSA = Signature.getInstance("SHA256withRSA");
        SignedObject signedObject = new SignedObject(datas, aPrivate, sha256withRSA);
        byte[] signature = signedObject.getSignature();
        //校验签名
        sha256withRSA.update(signature);
        boolean verify = signedObject.verify(aPublic, sha256withRSA);
        System.out.println(verify);

    }
}
