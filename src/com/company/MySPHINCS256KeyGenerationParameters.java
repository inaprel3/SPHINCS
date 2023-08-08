package com.company;

import java.security.SecureRandom;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256KeyGenerationParameters;

/* Параметры для генерации ключей SPHINCS+. */
public class MySPHINCS256KeyGenerationParameters extends SPHINCS256KeyGenerationParameters {
    private final byte[] seed;

    public MySPHINCS256KeyGenerationParameters(SecureRandom random, Digest treeDigest, byte[] seed) {
        super(random, treeDigest);
        this.seed = seed;
    }

    public byte[] getSeed() {
        return seed;
    }
}

/* Другие параметры для генерации ключей SPHINCS+с (сжатие с использованием SHA-256). */
class MySPHINCS256cKeyGenerationParameters extends SPHINCS256KeyGenerationParameters {
    private final byte[] seed;

    public MySPHINCS256cKeyGenerationParameters(SecureRandom random, Digest treeDigest, byte[] seed) {
        super(random, treeDigest);
        this.seed = seed;
    }

    public byte[] getSeed() {
        return seed;
    }
}
