package com.company;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.sphincs.*;

import java.security.SecureRandom;

/* Пример использования алгоритма SPHINCS+ для электронной цифровой подписи. */
public class SPHINCSPlusSignatureExample {

    public static void main(String[] args) throws CryptoException {
        // Инициализация хеш-функции SHA-256
        Digest digest = new SHA256Digest();

        // Создание генератора случайных чисел
        SecureRandom random = new SecureRandom();

        // Генерация случайного сида длиной 32 байта
        byte[] seed = new byte[32];
        random.nextBytes(seed);

        // Генерация ключевой пары для алгоритма SPHINCS+
        AsymmetricCipherKeyPair sphincsKeyPair = generateSPHINCSKeyPair(random, digest, seed);

        // Генерация ключевой пары для алгоритма SPHINCS+с (сжатие с использованием SHA-256)
        AsymmetricCipherKeyPair sphincsCKeyPair = generateSPHINCS256cKeyPair(random, digest, seed);

        // Ваше сообщение, которое требуется подписать
        byte[] message = "Hello, World!".getBytes();

        // Хеширование сообщения
        byte[] hashedMessage = hashMessage(digest, message);

        // Создание подписи с использованием алгоритма SPHINCS+
        byte[] signature = signMessage(digest, sphincsKeyPair, hashedMessage, random);
        boolean isValid = verifySignature(digest, sphincsKeyPair.getPublic(), hashedMessage, signature);
        System.out.println("SPHINCS+ Signature is valid: " + isValid);

        // Создание подписи с использованием алгоритма SPHINCS+с
        byte[] cSignature = signMessage(digest, sphincsCKeyPair, hashedMessage, random);
        boolean isCValid = verifySignature(digest, sphincsCKeyPair.getPublic(), hashedMessage, cSignature);
        System.out.println("SPHINCS+с Signature is valid: " + isCValid);
    }

    /* Генерация ключевой пары для алгоритма SPHINCS+. */
    private static AsymmetricCipherKeyPair generateSPHINCSKeyPair(SecureRandom random, Digest digest, byte[] seed) {
        SPHINCS256KeyPairGenerator keyPairGenerator = new SPHINCS256KeyPairGenerator();
        SPHINCS256KeyGenerationParameters keyGenParams = new MySPHINCS256KeyGenerationParameters(random, digest, seed);
        keyPairGenerator.init(keyGenParams);
        return keyPairGenerator.generateKeyPair();
    }

    /* Генерация ключевой пары для алгоритма SPHINCS+с (сжатие с использованием SHA-256). */
    private static AsymmetricCipherKeyPair generateSPHINCS256cKeyPair(SecureRandom random, Digest digest, byte[] seed) {
        SPHINCS256KeyPairGenerator keyPairGenerator = new SPHINCS256KeyPairGenerator();
        SPHINCS256KeyGenerationParameters keyGenParams = new MySPHINCS256cKeyGenerationParameters(random, digest, seed);
        keyPairGenerator.init(keyGenParams);
        return keyPairGenerator.generateKeyPair();
    }

    /* Хеширование сообщения с использованием заданной хеш-функции. */
    private static byte[] hashMessage(Digest digest, byte[] message) {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(message, 0, message.length);
        digest.doFinal(hash, 0);
        return hash;
    }

    /* Создание подписи для сообщения с использованием алгоритма SPHINCS+. */
    private static byte[] signMessage(Digest digest, AsymmetricCipherKeyPair keyPair, byte[] hashedMessage, SecureRandom random) throws CryptoException {
        SPHINCS256Signer signer = new SPHINCS256Signer(digest, digest);
        AsymmetricKeyParameter privateKey = keyPair.getPrivate();
        ParametersWithRandom params = new ParametersWithRandom(privateKey, random);
        signer.init(true, params);
        byte[] signature = signer.generateSignature(hashedMessage);
        return signature;
    }

    /* Проверка подписи для сообщения с использованием алгоритма SPHINCS+. */
    private static boolean verifySignature(Digest digest, AsymmetricKeyParameter publicKey, byte[] hashedMessage, byte[] signature) {
        SPHINCS256Signer signer = new SPHINCS256Signer(digest, digest);
        signer.init(false, publicKey);
        return signer.verifySignature(hashedMessage, signature);
    }
}
