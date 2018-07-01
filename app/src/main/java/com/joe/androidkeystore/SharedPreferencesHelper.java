package com.joe.androidkeystore;

import android.content.Context;
import android.content.SharedPreferences;


public class SharedPreferencesHelper {

    private static final String SHARED_PREF_NAME = "KEYSTORE_SETTING";

    private static final String PREF_KEY_AES = "PREF_KEY_AES";
    private static final String PREF_KEY_IV = "PREF_KEY_IV";
    private static final String PREF_KEY_INPUT = "PREF_KEY_INPUT";

    private SharedPreferences sharedPreferences;



    public SharedPreferencesHelper(Context context){
        sharedPreferences = context.getSharedPreferences(SHARED_PREF_NAME, Context.MODE_PRIVATE);
    }


    private String getString(String key) {
        return sharedPreferences.getString(key, "");
    }

    private void putString(String key, String value) {
        sharedPreferences.edit()
                .putString(key, value)
                .apply();
    }

    private boolean getBoolean(String key) {
        return sharedPreferences.getBoolean(key, false);
    }

    private void putBoolean(String key, boolean value) {
        sharedPreferences.edit()
                .putBoolean(key, value)
                .apply();
    }




    public void setIV(String value) {
        putString(PREF_KEY_IV, value);
    }

    public String getIV() {
        return getString(PREF_KEY_IV);
    }

    public void setAESKey(String value) {
        putString(PREF_KEY_AES, value);
    }

    public String getAESKey() {
        return getString(PREF_KEY_AES);
    }

    public void setInput(String value) {
        putString(PREF_KEY_INPUT, value);
    }

    public String getInput() {
        return getString(PREF_KEY_INPUT);
    }


}