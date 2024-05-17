package com.example.test

import android.os.Bundle
import android.util.Base64
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher

internal class MainActivity : AppCompatActivity(R.layout.main_layout) {

    private val provider = BouncyCastleProvider()
    private val cipher = Cipher.getInstance(TRANSFORMATION, provider)

    private fun generateRsaKeyPair(): KeyPair {
        val rsaGenerator = KeyPairGenerator.getInstance(KEY_PAIR_TYPE_RSA, provider)
            .apply {
                initialize(
                    RSAKeyGenParameterSpec(
                        ENCRYPTION_KEYSIZE_2048,
                        RSAKeyGenParameterSpec.F0
                    )
                )
            }

        return rsaGenerator.generateKeyPair()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val keyPair = generateRsaKeyPair()
        val encrypted = encrypt(TO_ENCRYPT, keyPair.public)
        val decrypted = decrypt(encrypted, keyPair.private)

        findViewById<TextView>(R.id.toEncrypt).text = """$TEXT$TO_ENCRYPT"""
        findViewById<TextView>(R.id.encrypted).text = """$TEXT$encrypted"""
        findViewById<TextView>(R.id.decrypted).text = """$TEXT$decrypted"""
    }

    private fun encrypt(toEncrypt: String, publicKey: PublicKey): String {
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encrypted = cipher.doFinal(toEncrypt.toByteArray())
        return encrypted.toBase64()
    }

    private fun decrypt(toDecrypt: String, private: PrivateKey): String {
        cipher.init(Cipher.DECRYPT_MODE, private)
        return String(cipher.doFinal(toDecrypt.fromBase64ToByteArray()))
    }

    private fun ByteArray.toBase64(): String = Base64.encodeToString(this, Base64.NO_WRAP)
    private fun String.fromBase64ToByteArray(): ByteArray = Base64.decode(this, Base64.DEFAULT)

    private companion object {
        const val TEXT = "Text: "

        const val TO_ENCRYPT = "THIS IS TEXT TO ENCODE"

        const val KEY_PAIR_TYPE_RSA = "RSA"
        const val TRANSFORMATION = "RSA/ECB/PKCS1Padding"
        const val ENCRYPTION_KEYSIZE_2048 = 2048
    }
}