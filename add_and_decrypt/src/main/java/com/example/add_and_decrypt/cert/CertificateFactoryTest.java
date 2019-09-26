package com.example.add_and_decrypt.cert;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * CertificateFactory 测试
 * @author Ryze
 * @date 2019-09-26 10:20
 */
public class CertificateFactoryTest {
    public static void main(String[] args) throws CertificateException, IOException {
        //加载证书
        CertificateFactory instance = CertificateFactory.getInstance("X.509");
        FileInputStream stream = new FileInputStream("D:\\x.keystore");
        Certificate certificate = instance.generateCertificate(stream);
        stream.close();
    }
}
