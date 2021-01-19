package com.yx.encryptionalgorithmhook;

import java.security.MessageDigest;

/**
 * @author glsite.com
 * @version $Rev$
 * @des ${TODO}
 * @updateAuthor $Author$
 * @updateDes ${TODO}
 */
public class Md5 {
    /*
    返回类型    方法重载
    byte[]	digest()
    通过执行最后的操作（如填充）来完成哈希计算。
    byte[]	digest(byte[] input)
    使用指定的字节数组对摘要执行最终更新，然后完成摘要计算。
    int	digest(byte[] buf, int offset, int len)
    通过执行最后的操作（如填充）来完成哈希计算。


    void	update(byte input)
    使用指定的字节更新摘要。
    void	update(byte[] input)
    使用指定的字节数组更新摘要。
    void	update(byte[] input, int offset, int len)
    使用指定的字节数组从指定的偏移量开始更新摘要。
    void	update(ByteBuffer input)
    使用指定的ByteBuffer更新摘要。
    *
    *
    * */
    public static String md5_1(String args) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5", "BC");
        md.update(args.getBytes());
        return Utils.byteToHexString(md.digest());
    }

    public static String md5_2(String args) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5", "BC");
        md.update(args.getBytes(), 2, 5);
        return Utils.byteToHexString(md.digest("xiaojianbang".getBytes()));
    }

}
