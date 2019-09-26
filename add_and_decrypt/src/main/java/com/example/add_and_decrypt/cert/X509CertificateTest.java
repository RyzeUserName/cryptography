package com.example.add_and_decrypt.cert;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * X509Certificate 测试
 * @author Ryze
 * @date 2019-09-26 10:50
 */
public class X509CertificateTest {
    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        FileInputStream stream = new FileInputStream("D:\\x.keystore");
        KeyStore jks = KeyStore.getInstance("JKS");
        //加载密钥库
        jks.load(stream,"password".toCharArray());
        stream.close();
        //获取证书
        X509Certificate x509Certificate = (X509Certificate) jks.getCertificate("别名");
        //根据证书获取 签名对象
        Signature instance = Signature.getInstance(x509Certificate.getSigAlgName());
    }
}
