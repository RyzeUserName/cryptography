package com.example.add_and_decrypt.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * DigestInputStream 测试
 * @author Ryze
 * @date 2019-09-23 14:19
 */
public class DigestInputStreamTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        byte[] bytes = "sha".getBytes();
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        DigestInputStream digestInputStream = new DigestInputStream(new ByteArrayInputStream(bytes), md5);
        //读 一定需要读
        digestInputStream.read(bytes, 0, bytes.length);
        byte[] digest = digestInputStream.getMessageDigest().digest();
        //关流
        digestInputStream.close();
        MessageDigestTest.printC(digest);
    }
}
