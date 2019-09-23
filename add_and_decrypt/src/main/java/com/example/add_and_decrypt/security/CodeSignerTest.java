package com.example.add_and_decrypt.security;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.CodeSigner;
import java.security.Timestamp;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;

/**
 * CodeSigner 测试
 * @author Ryze
 * @date 2019-09-23 18:04
 */
public class CodeSignerTest {
    public static void main(String[] args) throws CertificateException, FileNotFoundException {
        //证书 生成
        CertificateFactory x509 = CertificateFactory.getInstance("X509");
        FileInputStream fileInputStream = new FileInputStream("D:\\x.cer");
        CertPath certificate = x509.generateCertPath(fileInputStream);
        //生成 timestamp
        Timestamp timestamp = new Timestamp(new Date(), certificate);
        //实例化
        CodeSigner codeSigner = new CodeSigner(certificate, timestamp);
        //比较
        codeSigner.equals(new CodeSigner(certificate, timestamp));
    }
}
