package com.example.joe.keystoredemo;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;


public class KeyStoreHelper {

    private static final String TAG = "KEYSTORE";

    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";

    private static final String KEYSTORE_ALIAS = "KEYSTORE_DEMO";

    private KeyStore keyStore;

    public KeyStoreHelper(Context context) {
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (!keyStore.containsAlias(KEYSTORE_ALIAS)) {
                generateKey(context);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    private void generateKey(Context context) throws Exception {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            generateRSAKey_AboveApi23();

        } else {
            generateRSAKey_BelowApi23(context);
        }
    }


    @RequiresApi(api = Build.VERSION_CODES.M)
    private void generateRSAKey_AboveApi23() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER);


        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec
                .Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build();

        keyPairGenerator.initialize(keyGenParameterSpec);
        keyPairGenerator.generateKeyPair();

    }

    private void generateRSAKey_BelowApi23(Context context) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 100);

        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(KEYSTORE_ALIAS)
                .setSubject(new X500Principal("CN=" + KEYSTORE_ALIAS))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER);

        keyPairGenerator.initialize(spec);
        keyPairGenerator.generateKeyPair();
    }


    public String encrypt(String plainText) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                return encryptRSA_AboveApi23(plainText);

            } else {
                return encryptRSA_BelowApi23(plainText);
            }

        } catch (Exception e) {
            Log.d(TAG, Log.getStackTraceString(e));
            return "";
        }
    }

    public String decrypt(String encryptedText) {

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                return decryptRSA_AboveApi23(encryptedText);

            } else {
                return decryptRSA_BelowApi23(encryptedText);
            }
        } catch (Exception e) {
            Log.d(TAG, Log.getStackTraceString(e));
            return "";
        }

    }


    private String encryptRSA_AboveApi23(String plainText) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, NoSuchPaddingException, InvalidKeyException, IOException {
        PublicKey publicKey = keyStore.getCertificate(KEYSTORE_ALIAS).getPublicKey();

        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
        cipherOutputStream.write(plainText.getBytes());
        cipherOutputStream.close();

        return Base64.encodeToString(outputStream.toByteArray(), Base64.DEFAULT);
    }


    private String decryptRSA_AboveApi23(String encryptedText) throws Exception {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEYSTORE_ALIAS, null);

        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decodedBytes = Base64.decode(encryptedText, Base64.DEFAULT);


        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(decodedBytes), cipher);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte) nextByte);
        }

        byte[] bytes = new byte[values.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i).byteValue();
        }

        return new String(bytes);
    }


    private String encryptRSA_BelowApi23(String plainText) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, NoSuchPaddingException, InvalidKeyException, IOException {
        PublicKey publicKey = keyStore.getCertificate(KEYSTORE_ALIAS).getPublicKey();

        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
        cipherOutputStream.write(plainText.getBytes("UTF-8"));
        cipherOutputStream.close();

        return Base64.encodeToString(outputStream.toByteArray(), Base64.DEFAULT);
    }

    private String decryptRSA_BelowApi23(String encryptedText) throws Exception {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEYSTORE_ALIAS, null);

        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decodedBytes = Base64.decode(encryptedText.getBytes(), Base64.DEFAULT);

        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(decodedBytes), cipher);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte) nextByte);
        }

        byte[] bytes = new byte[values.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i).byteValue();
        }

        return new String(bytes);
    }

}
