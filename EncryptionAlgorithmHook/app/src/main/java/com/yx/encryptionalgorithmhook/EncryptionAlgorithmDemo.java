package com.yx.encryptionalgorithmhook;

import android.util.Base64;
import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.math.BigInteger;
import java.security.MessageDigest; //md5  sha

import java.security.PublicKey;

import javax.crypto.Mac; //mac

import javax.crypto.Cipher; //des  3des aes  mac


/**
 * @author yx
 * @version $Rev$
 * @des hook Encryption Algorithm
 * @updateAuthor $Author$
 * @updateDes ${TODO}
 */

public class EncryptionAlgorithmDemo implements IXposedHookLoadPackage {

    private static String TAG = null;
    private static String currentPackageName = null;

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lPParam) throws Throwable {

        currentPackageName = lPParam.packageName;
        TAG = new StringBuffer("YxHooking:").append(':').append(currentPackageName).toString();

        //hook md5 sha算法
        XposedBridge.hookAllMethods(XposedHelpers.findClass("java.security.MessageDigest", lPParam.classLoader),
                "digest",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        //不会中断程序，打印出堆栈信息
                        //Log.e(TAG,"stack",new Throwable("stack dump"));
                        MessageDigest md = (MessageDigest)param.thisObject;
                        String algorithm = md.getAlgorithm();
                        if(param.args.length == 3){
                            byte [] params = (byte [])param.args[0];
                            int offset = ((Integer) param.args[1]).intValue();
                            int size = ((Integer) param.args[2]).intValue();
                            byte[] keyByte = new byte[size];
                            System.arraycopy(params,offset,keyByte,0,size);
                            Utils.logData(keyByte,TAG,algorithm +"#digest 3 ");
                            
                        } else if (param.args.length == 1){
                            byte [] params = (byte [])param.args[0];
                            Utils.logData(params,TAG,algorithm+"#digest#");
                        }
                        byte [] result = (byte[])param.getResult();
                        Utils.logData(result,TAG,algorithm+"#digest result");
                    }

                }
        );
        //hook md5 sha update
        XposedBridge.hookAllMethods(XposedHelpers.findClass("java.security.MessageDigest", lPParam.classLoader),
                "update",
                new XC_MethodHook() {

                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        MessageDigest md = (MessageDigest)param.thisObject;
                        String algorithm = md.getAlgorithm();
                        byte [] params = (byte [])param.args[0];
                        Utils.logData(params,TAG,algorithm+"#update#");
                    }
                }

        );

        //主要hook 秘钥 des  3des aes  mac
        XposedBridge.hookAllConstructors(XposedHelpers.findClass("javax.crypto.spec.SecretKeySpec", lPParam.classLoader),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] secreteKey = (byte[]) param.args[0];
                        int offset = 0;
                        int size = 0;
                        String algorithm = null;
                        if (param.args.length != 2){
                            offset = ((Integer) param.args[1]).intValue();
                            size = ((Integer) param.args[2]).intValue();
                            algorithm = (String) param.args[3];
                        }else {
                            size = secreteKey.length;
                            algorithm = (String) param.args[1];
                        }
                        byte[] keyByte = new byte[size];
                        System.arraycopy(secreteKey,offset,keyByte,0,size);

                        Utils.logData(keyByte,TAG,algorithm+"#SecretKeySpec ");
                    }

                }
        );


        //hook mac算法
        XposedBridge.hookAllMethods(XposedHelpers.findClass("javax.crypto.Mac", lPParam.classLoader),
                "doFinal",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args.length == 2)return;
                        Mac mac = (Mac)param.thisObject;
                        String algorithm = mac.getAlgorithm();
                        if (param.args.length == 1){
                            byte [] params = (byte [])param.args[0];
                            Utils.logData(params,TAG,algorithm+"#digest ");
                        }
                        byte [] result = (byte[])param.getResult();
                        Utils.logData(result,TAG,algorithm+"#digest result");
                    }
                }
        );

        //hook mac update
        XposedBridge.hookAllMethods(XposedHelpers.findClass("javax.crypto.Mac", lPParam.classLoader),
                "update",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Mac mac= (Mac)param.thisObject;
                        String algorithm = mac.getAlgorithm();
                        byte [] params = (byte [])param.args[0];
                        Utils.logData(params,TAG,algorithm+"#update ");
                    }
                }

        );

        //hook IV向量
        XposedBridge.hookAllConstructors(XposedHelpers.findClass("javax.crypto.spec.IvParameterSpec", lPParam.classLoader),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        //Log.e(TAG,new Throwable("stack dump"));
                        byte[] ivParameter = (byte[]) param.args[0];
                        int offset = 0;
                        int size = 0;
                        if (param.args.length != 1){
                            offset = ((Integer) param.args[1]).intValue();
                            size = ((Integer) param.args[2]).intValue();
                        }else {
                            size = ivParameter.length;
                        }
                        byte[] ivByte = new byte[size];
                        System.arraycopy(ivParameter,offset,ivByte,0,size);
                        Utils.logData(ivByte,TAG,"#ivParameter ");

                    }
                }

        );

        //hook Cipher des rsa 3des aes算法
        XposedBridge.hookAllMethods(XposedHelpers.findClass("javax.crypto.Cipher", lPParam.classLoader),
                "doFinal",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Cipher cipher = (Cipher)param.thisObject;
                        String algorithm = cipher.getAlgorithm();
                        byte [] params = (byte [])param.args[0];
                        if (param.args.length == 3){
                            int offset = ((Integer) param.args[1]).intValue();
                            int size = ((Integer) param.args[2]).intValue();
                            byte[] databyte = new byte[size];
                            System.arraycopy(params,offset,databyte,0,size);
                            Utils.logData(databyte,TAG,algorithm+"#doFinal ");
                        }else if (param.args.length == 1){
                            Utils.logData(params,TAG,algorithm+"#Cipher ");
                        }

                        byte [] result = (byte[])param.getResult();
                        Utils.logData(result,TAG,algorithm+"#Cipher result");

                    }
                }

        );

        //hook Cipher update
        XposedBridge.hookAllMethods(XposedHelpers.findClass("javax.crypto.Cipher", lPParam.classLoader),
                "update",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Cipher cipher = (Cipher)param.thisObject;
                        String algorithm = cipher.getAlgorithm();
                        byte [] params = (byte [])param.args[0];
                        Utils.logData(params,TAG,algorithm+"#Cipher ");
                    }
                }

        );
        // hook rsakey  base64
        XposedBridge.hookAllConstructors(XposedHelpers.findClass("java.security.spec.X509EncodedKeySpec", lPParam.classLoader),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        byte [] params = (byte [])param.args[0];
                        String dataBase64 = Base64.encodeToString(params, 0);
                        Log.d(TAG,"#X509EncodedKeySpec Base64#" + dataBase64);
                        Log.d(TAG,"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    }
                }
        );
        //hook RSAPublicKey
        XposedBridge.hookAllConstructors(XposedHelpers.findClass("java.security.interfaces.RSAPublicKey", lPParam.classLoader),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String n = ((BigInteger) param.args[0]).toString(16);
                        String e = ((BigInteger) param.args[1]).toString(16);
                        Log.d(TAG,"RSAPublicKey#"+n + "#" +e);
                        Log.d(TAG,"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    }
                }
        );

        //hook java.security.KeyFactory
        XposedBridge.hookAllMethods(XposedHelpers.findClass("java.security.KeyFactory", lPParam.classLoader),
                "generatePublic",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        PublicKey result = (PublicKey) param.getResult();
                        byte [] params= result.getEncoded();
                        Utils.logData(params,TAG,"#RsaKeyFactory ");
                    }
                }
        );

    }

}
