package ltechnologies.onionphone.onionvpn.prefs

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import timber.log.Timber

/**
 * AES-256-GCM for the OpenVPN user password in DataStore.
 *
 * Stored form: `ovpn-gcm:` + Base64(IV ‖ ciphertext ‖ tag).
 * Plaintext leftovers (no prefix) are treated as legacy and re-encrypted on next write.
 */
object OpenVpnPasswordCipher {
    const val PREFIX = "ovpn-gcm:"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "onionvpn_openvpn_auth"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val IV_LEN = 12

    fun encrypt(plain: String): String {
        if (plain.isEmpty()) return ""
        if (plain.startsWith(PREFIX)) return plain
        return runCatching {
            val key = secretKey()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            require(iv.size == IV_LEN) { "unexpected GCM IV length ${iv.size}" }
            val sealed = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
            val packed = ByteArray(iv.size + sealed.size)
            System.arraycopy(iv, 0, packed, 0, iv.size)
            System.arraycopy(sealed, 0, packed, iv.size, sealed.size)
            PREFIX + Base64.encodeToString(packed, Base64.NO_WRAP)
        }.getOrElse { err ->
            Timber.e(err, "OpenVPN password encrypt failed — refusing plaintext persist")
            ""
        }
    }

    fun decrypt(stored: String): String {
        if (stored.isEmpty()) return ""
        if (!stored.startsWith(PREFIX)) {
            // Legacy plaintext — returned as-is so start still works; next update re-encrypts.
            return stored
        }
        return runCatching {
            val packed = Base64.decode(stored.removePrefix(PREFIX), Base64.NO_WRAP)
            require(packed.size > IV_LEN) { "ciphertext too short" }
            val iv = packed.copyOfRange(0, IV_LEN)
            val sealed = packed.copyOfRange(IV_LEN, packed.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            String(cipher.doFinal(sealed), Charsets.UTF_8)
        }.getOrElse { err ->
            Timber.e(err, "OpenVPN password decrypt failed")
            ""
        }
    }

    private fun secretKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return gen.generateKey()
    }
}
