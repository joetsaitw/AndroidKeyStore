package com.example.joe.keystoredemo;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {


    EditText editTextInput;


    TextView textEncrypt;
    TextView textDecrypt;


    Button buttonEncrypt;
    Button buttonDecrypt;
    Button buttonSave;

    KeyStoreHelper keyStoreHelper;
    SharedPreferences sharedPreferences;

    private final String PREF_KEY_INPUT = "PREF_KEY_INPUT";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        keyStoreHelper = new KeyStoreHelper(getApplicationContext());
        sharedPreferences = getPreferences(Context.MODE_PRIVATE);

        initView();
        initEditTextInput();
        setupButton();

    }

    private void initEditTextInput() {
        String encryptedText = getString(PREF_KEY_INPUT);
        String plainInput = keyStoreHelper.decrypt(encryptedText);
        editTextInput.setText(plainInput);
    }

    private void setupButton() {
        buttonEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String encryptedText = keyStoreHelper.encrypt(editTextInput.getText().toString());
                textEncrypt.setText(encryptedText);
            }
        });

        buttonDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String decryptedText = keyStoreHelper.decrypt(textEncrypt.getText().toString());
                textDecrypt.setText(decryptedText);
            }
        });

        buttonSave.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                putString(PREF_KEY_INPUT, textEncrypt.getText().toString());
                Toast.makeText(getApplicationContext(), "Successfully saved!", Toast.LENGTH_SHORT).show();
            }
        });
    }


    private void initView() {
        editTextInput = (EditText) findViewById(R.id.editText_input);
        textEncrypt = (TextView) findViewById(R.id.text_encrypt);
        textDecrypt = (TextView) findViewById(R.id.text_decrypt);
        buttonEncrypt = (Button) findViewById(R.id.button_encrypt);
        buttonDecrypt = (Button) findViewById(R.id.button_decrypt);
        buttonSave = (Button) findViewById(R.id.button_save);
    }


    private String getString(String key) {
        return sharedPreferences.getString(key, "");
    }

    private void putString(String key, String value) {
        sharedPreferences.edit()
                .putString(key, value)
                .apply();
    }
}
