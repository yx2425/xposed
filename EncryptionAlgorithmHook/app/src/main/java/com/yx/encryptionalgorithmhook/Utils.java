package com.yx.encryptionalgorithmhook;

import android.util.Base64;
import android.util.Log;

/**
 * @author glsite.com
 * @version $Rev$
 * @des ${TODO}
 * @updateAuthor $Author$
 * @updateDes ${TODO}
 */
public class Utils {

    public static String byteToHexString(byte[] by) {
        StringBuffer SB = new StringBuffer();
        for (byte k : by) {
            int j = k;
            if (k < 0) {
                j = k + 256;
            }
            if (j < 16) {
                SB.append("0");
            }
            SB.append(Integer.toHexString(j));
        }
        return SB.toString();
    }

    public static byte[] hexStringToByte(byte[] b) {
        if (b.length % 2 != 0) {
            throw new IllegalArgumentException("长度不是偶数");
        }
        byte[] b2 = new byte[(b.length / 2)];
        for (int n = 0; n < b.length; n += 2) {
            b2[n / 2] = (byte) Integer.parseInt(new String(b, n, 2), 16);
        }
        return b2;
    }

    public static void logData(byte[] params,String TAG,String algorithmInfo ){
        String data = new String(params);
        String dataHex = Utils.byteToHexString(params);
        String dataBase64 = Base64.encodeToString(params, 0);
        Log.d(TAG,algorithmInfo+"#data#" + data);
        Log.d(TAG,algorithmInfo+"#dataHex#" + dataHex);
        Log.d(TAG,algorithmInfo+"#dataBase64#" + dataBase64);
        Log.d(TAG,"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    }

}
