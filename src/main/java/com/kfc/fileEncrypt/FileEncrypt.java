package com.kfc.fileEncrypt;

import com.kfc.fileEncrypt.utils.CertificateFileUtils;
import com.kfc.fileEncrypt.utils.HexUtils;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

/**
 * 文件加密
 *
 * @author: Chenkf
 * @create: 2021/05/15
 **/
public class FileEncrypt {

    public static final String JCE_ALG_RC2 = "RC2/CBC/PKCS5Padding";

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        //用于加密的文件
        String filePath = "C:\\Users\\chenkf\\Desktop\\山西代收付资料\\WEB标准文件模板\\代付模板.xls";
        //公钥路径
        String pkPath = "D:\\ssl\\test.cer";
        PublicKey pk = CertificateFileUtils.getPublicKeyByFile(pkPath);

        //开始加密
        System.out.println("开始加密.....");
        byte[] encryptFileBytes = encryptFile(filePath, pk);

        System.out.println("加密文件成功，加密文件的16进制为:");
        System.out.println(HexUtils.bytesToHex(encryptFileBytes));

        //私钥路径
        String privateKeyPath = "D:\\ssl\\test.pfx";
        //私钥密码
        String privateKeyPassword = "12345678";
        PrivateKey privateKey = CertificateFileUtils.getPrivateKeyByFile(privateKeyPath, privateKeyPassword);
        //开始解密
        System.out.println("开始解密.....");
        //解密后明文文件路径
        String plainFilePath = "D:\\123.xls";
        decryptFile(encryptFileBytes, privateKey, plainFilePath);
        System.out.println("解密成功，解密后的明文文件为：" + plainFilePath);
    }


    /**
     * 解密文件
     *
     * @param msg
     * @param privateKey
     * @param plainFilePath 明文文件路径
     * @throws Exception
     */
    public static void decryptFile(byte[] msg, PrivateKey privateKey, String plainFilePath) throws Exception {
        int pos = 0;
        if (msg != null && msg.length >= 150) {
            //读取4字节头，检查是否为加密标识，如果是0x efdcb1a2则继续处理，否则按明文处理
            byte[] codeBytes = new byte[4];
            System.arraycopy(msg, pos, codeBytes, 0, 4);
            pos += 4;

            //版本号，检查版本号是否为‘10’
            String version = new String(msg, pos, 2);
            System.out.println("解析文件头version=" + version);
            pos += 2;

            //读取加密对称密钥EK
            byte[] ek = new byte[128];
            System.arraycopy(msg, pos, ek, 0, 128);
            pos += 128;

            //用自己的私钥将EK解密，得到SK，计算方法SK=D(EK,PrivateKey, RSA/ECB/PKCS1Padding)
            byte[] sk = decryptEk(ek, privateKey);

            //读取哈希值H
            byte[] h = new byte[16];
            System.arraycopy(msg, pos, h, 0, 16);
            pos += 16;

            //并用对称密钥解密哈希值，得到H1=read(F) --这一步需要？
            //byte[] h1 =
            File decryptFile = new File(plainFilePath);
            FileUtils.deleteQuietly(decryptFile);
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            while (pos < msg.length - 1) {
                //读取密文块的长度Li，根据Li申请内存，再读取密文内容Ei
                int li = ByteBuffer.wrap(msg, pos, 4).getInt();
                pos += 4;

                byte[] ei = new byte[li];
                System.arraycopy(msg, pos, ei, 0, li);
                pos += li;

                //用SK对Ei进行解密，得到明文块Di，Di=D(Ei,SK, RC2/CBC/PKCS5Padding)
                byte[] di = DecryptWithSk(ei, sk);
                messageDigest.update(di);
                FileUtils.writeByteArrayToFile(decryptFile, di, true);
            }
            byte[] hash = messageDigest.digest();
            //判断哈希得到的值和文件中的哈希值是否相等
            System.out.println("对文件进行hash值为：" + HexUtils.bytesToHex(hash));
            System.out.println("文件包含的hash值为：" + HexUtils.bytesToHex(h));
            System.out.println("判断hash值是否相等：" + Arrays.equals(hash, h));
        } else {
            throw new RuntimeException("加密文件格式不合要求，必须要大于150字节");
        }
    }

    /**
     * 加密文件
     * @param filePath  要加密的文件路径
     * @param pk
     * @return
     * @throws Exception
     */
    public static byte[] encryptFile(String filePath, PublicKey pk) throws Exception {
        //1、产生对称密钥SK，记为SK=GenKey(RC2/CBC/PKCS5Padding) 128字节
        byte[] sk = generateSk();
        System.out.println("产生的对称密钥长度：" + sk.length);

        //2、读取对方公钥，用公钥加密对称密钥，EK=E(SK,PK, RSA/ECB/PKCS1Padding)
        byte[] ek = encryptSk(sk, pk);

        //3、向密文文件写入文件头write(F,0x efdcb1a2);write(F,’10’);write(F,EK);write(F,0x00[16]);最后写入的16个长的0x00用于占位
        byte[] headBytes = generateFileHead(ek);
        ByteArrayOutputStream out = null;
        InputStream is = null;
        try {
            out = new ByteArrayOutputStream();
            out.write(headBytes);
            is = new FileInputStream(filePath);
            byte[] flush = new byte[1024];//缓冲容器
            int len = -1;//接收长度


            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            while ((len = is.read(flush)) != -1) {
                //4、读取文件内容中的一个数据块Di，对其进行对称加密，记作Ei=E(Di,SK)
                System.out.println("单次读取length=" + len);
                byte[] di = new byte[len];
                System.arraycopy(flush, 0, di, 0, len);
                byte[] ei = encryptDiWithSk(di, sk);
                //5、对Di进行哈希H(Di)，其中H表示分布哈希算法，即执行多步哈希操作，最后一步输出结果
                messageDigest.update(di);
                //6、将密文块的长度Li和密文Ei写入文件，write(F,Li)，write(F,Ei)
                addLiAndEi(out, ei, ei.length);
            }
            byte[] hash = messageDigest.digest();
            byte[] result = out.toByteArray();
            System.arraycopy(hash, 0, result, 134, 16);
            return result;

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } finally {
            try {
                if (null != is) {
                    is.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                if (null != out) {
                    out.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    /**
     * 生成对称密钥SK
     *
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] generateSk() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyGenerator keygenerator = KeyGenerator.getInstance("RC2", BouncyCastleProvider.PROVIDER_NAME);
        SecureRandom sr = new SecureRandom();
        keygenerator.init(128, sr);
        SecretKey symKey = keygenerator.generateKey();
        return symKey.getEncoded();
    }

    /**
     * 用RSA加密对称密钥SK，得到EK
     *
     * @param sk 对称密钥
     * @param pk 公钥
     * @return ek
     */
    public static byte[] encryptSk(byte[] sk, PublicKey pk) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, pk);
        return cipher.doFinal(sk);
    }

    /**
     * 用RSA解密EK，得到SK
     *
     * @param ek
     * @param privateKey 中心私钥
     * @return sk
     */
    public static byte[] decryptEk(byte[] ek, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(2, privateKey);
            return cipher.doFinal(ek);
        } catch (Exception var4) {
            var4.printStackTrace();
            return null;
        }
    }



    /**
     * 使用SK对文件块进行加密
     *
     * @param di
     * @param sk
     * @return
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] encryptDiWithSk(byte[] di, byte[] sk) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        byte[] default_iv = new byte[8];
        IvParameterSpec IV = new IvParameterSpec(default_iv);
        SecretKeySpec sks = new SecretKeySpec(sk, "RC2");
        Cipher cipher = Cipher.getInstance("RC2/CBC/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
        RC2ParameterSpec rc2ps = new RC2ParameterSpec(sk.length * 8, IV.getIV());
        cipher.init(Cipher.ENCRYPT_MODE, sks, rc2ps);
        return cipher.doFinal(di);
    }


    /**
     * 使用SK对密文进行解密，得到明文
     *
     * @param ei 密文
     * @param sk SK
     * @return 明文
     */
    public static byte[] DecryptWithSk(byte[] ei, byte[] sk) {
        try {
            SecretKeySpec sks = new SecretKeySpec(sk, "RC2");
            Cipher cipher = Cipher.getInstance("RC2/CBC/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
            byte[] default_iv = new byte[8];
            IvParameterSpec IV = new IvParameterSpec(default_iv);
            RC2ParameterSpec rc2ps = new RC2ParameterSpec(sk.length * 8, IV.getIV());
            cipher.init(2, sks, rc2ps);
            return cipher.doFinal(ei);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 将密文块的长度Li和密文Ei写入文件，write(F,Li)，write(F,Ei)
     *
     * @param buf 输出流
     * @param ei  要写入的加密数据
     * @param len 写入数据的长度
     */
    public static void addLiAndEi(ByteArrayOutputStream buf, byte[] ei, int len) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(0, len);
        buf.write(bb.array(), 0, 4);
        if (len > 0) {
            buf.write(ei, 0, len);
        }

    }


    /**
     * 生成加密文件头
     *
     * @param ek
     * @return
     */
    public static byte[] generateFileHead(byte[] ek) {
        //每一个字段要求必须填充，共计150字节
        byte[] msg = new byte[150];
        //标识码-固定填写0xefdcb1a2，表示该文件为密文，系统用于识别此文件是明文还是密文
        System.arraycopy(HexUtils.hexToByte("efdcb1a2"), 0, msg, 0, 4);
        //版本号-‘10’＿第一版
        System.arraycopy("10".getBytes(), 0, msg, 4, 2);
        //加密密钥
        System.arraycopy(ek, 0, msg, 6, 128);
        //哈希值
        System.arraycopy(new byte[16], 0, msg, 134, 16);
        return msg;
    }


}
