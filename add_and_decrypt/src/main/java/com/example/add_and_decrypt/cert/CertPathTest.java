package com.example.add_and_decrypt.cert;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * CertPath 测试
 * @author Ryze
 * @date 2019/9/26 22:29
 */
public class CertPathTest {
    public static void main(String[] args) throws CertificateException, CRLException, IOException {
        //加载证书
        CertificateFactory instance = CertificateFactory.getInstance("X.509");
        FileInputStream stream = new FileInputStream("D:\\x.keystore");
        //生成
        CertPath certPath = instance.generateCertPath(stream);
        stream.close();
    }
}
