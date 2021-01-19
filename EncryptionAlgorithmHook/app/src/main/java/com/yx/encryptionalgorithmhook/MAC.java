package com.yx.encryptionalgorithmhook;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author glsite.com
 * @version $Rev$
 * @des ${TODO}
 * @updateAuthor $Author$
 * @updateDes ${TODO}
 */
public class MAC {
    public static String mac_1(String args) throws Exception {
        SecretKey key = new SecretKeySpec("FridaHook".getBytes(), "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(key);
        mac.update(args.getBytes());
        return Utils.byteToHexString(mac.doFinal());
    }

    public static String mac_2(String args) throws Exception {
        SecretKey key = new SecretKeySpec("FridaHook".getBytes(), "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(key);
        mac.update(args.getBytes(), 2, 5);
        return Utils.byteToHexString(mac.doFinal("xiaojianbang".getBytes()));
    }

}
