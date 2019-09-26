package com.example.add_and_decrypt.cert;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.*;

/**
 * X509CRL 测试
 * @author Ryze
 * @date 2019-09-26 11:39
 */
public class X509CRLTest {
    public static void main(String[] args) throws CertificateException, IOException, CRLException {
        //加载证书
        CertificateFactory instance = CertificateFactory.getInstance("X.509");
        FileInputStream stream = new FileInputStream("D:\\x.keystore");
        X509Certificate certificate = (X509Certificate)instance.generateCertificate(stream);
        X509CRL crl = (X509CRL)instance.generateCRL(stream);
        //获取撤销证书列表
        X509CRLEntry revokedCertificate = crl.getRevokedCertificate(certificate);
        stream.close();
    }
}
