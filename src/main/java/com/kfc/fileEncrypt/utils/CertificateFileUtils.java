package com.kfc.fileEncrypt.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;

/**
 * 证书工具类，直接从文件获取证书
 *
 * @author: Chenkf
 * @create: 2021/05/16
 **/
public class CertificateFileUtils {

    /**
     * 获取X.509公钥
     * @param spath
     * @return
     * @throws Exception
     */
    public static PublicKey getPublicKeyByFile(String spath) throws Exception {

        Certificate cert = null;
        try {
            InputStream streamCert = new FileInputStream(spath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = cf.generateCertificate(streamCert);
        } catch (FileNotFoundException e1) {
            throw new RuntimeException("获取公钥证书不存在[" + spath + "]", e1);
        } catch (CertificateException e2) {
            throw new RuntimeException("获取公钥证书失败", e2);
        }
        return cert.getPublicKey();
    }

    /**
     * 通过密钥文件获取私钥
     *
     * @param pfxFile 密钥文件路径
     * @param passwd  密钥保存密码
     * @return PrivateKey
     */
    public static PrivateKey getPrivateKeyByFile(String pfxFile, String passwd) {
        PrivateKey key = null;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            char[] cPasswd = passwd.toCharArray();
            FileInputStream fis = null;
            try {
                fis = new FileInputStream(pfxFile);
                ks.load(fis, cPasswd);
                fis.close();
            } finally {
                if (fis != null) {
                    fis.close();
                    fis = null;
                }
            }
            Enumeration<String> aliasenum = ks.aliases();
            String keyAlias = null;
            while (aliasenum.hasMoreElements()) {
                keyAlias = (String) aliasenum.nextElement();
                key = (PrivateKey) ks.getKey(keyAlias, cPasswd);
                if (key != null)
                    break;
            }
        } catch (Exception e) {
            throw new RuntimeException("读取私钥文件失败", e);
        }
        return key;
    }
}
