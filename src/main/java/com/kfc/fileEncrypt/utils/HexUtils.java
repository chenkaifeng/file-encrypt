package com.kfc.fileEncrypt.utils;

/**
 * 字节数组与十六进制字符串转换工具
 * @author: Chenkf
 * @create: 2021/05/16
 **/
public class HexUtils {

    /**
     * byte数组转hex
     * @param b
     * @return
     */
    public static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            sb.append(String.format("%02x", b[i]));
        }
        return sb.toString();
    }

    /**
     * hex转byte数组
     * @param hex
     * @return
     */
    public static byte[] hexToByte(String hex){
        int m = 0, n = 0;
        int byteLen = hex.length() / 2; // 每两个字符描述一个字节
        byte[] ret = new byte[byteLen];
        for (int i = 0; i < byteLen; i++) {
            m = i * 2 + 1;
            n = m + 1;
            int intVal = Integer.decode("0x" + hex.substring(i * 2, m) + hex.substring(m, n));
            ret[i] = Byte.valueOf((byte)intVal);
        }
        return ret;
    }
}
