package com.example.add_and_decrypt.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * DigestOutputStream 测试
 * @author Ryze
 * @date 2019-09-23 14:45
 */
public class DigestOutputStreamTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        byte[] bytes = "sha".getBytes();
        MessageDigest md5 = MessageDigest.getInstance("md5");
        DigestOutputStream digestOutputStream = new DigestOutputStream(new ByteArrayOutputStream(), md5);
        //写
        digestOutputStream.write(bytes);
        byte[] digest = digestOutputStream.getMessageDigest().digest();
        //关流
        digestOutputStream.close();
        MessageDigestTest.printC(digest);
    }
}
