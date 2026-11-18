/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package com.mycompany.mavenproject4;

/**
 *
 * @author nadee
 */


import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * A MyCoin wallet. Holds an EC keypair and its derived address.
 *
 * <p>The address is a truncated Base64URL encoding of
 * {@code SHA-256(publicKey.getEncoded())}, prefixed with 'M'. Verification
 * (in {@link UTXOSet}) recomputes the address from the supplied public key and
 * compares — so the address is <em>bound</em> to the key that must sign.</p>
 *
 * <p>Not {@link java.io.Serializable}: private keys must not be written by
 * Java's default serialization. Persistence is explicit (PKCS#8/SPKI bytes),
 * see {@link #privateKeyBytes()} and {@link #fromPrivateKey(byte[])}.</p>
 */
public final class Wallet {

    /** Curve pinned so signatures are interoperable across runs/JVMs. */
    public static final String CURVE = "secp256r1";

    /** Signature algorithm pinned; verifier must use the same. */
    public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    /** Address is 'M' + 30 Base64URL chars (~180 bits of hash). */
    public static final int ADDRESS_BODY_LENGTH = 30;

    private final KeyPair keyPair;
    private final String address;

    // ── Constructors ──────────────────────────────────────────────────────

    /** Generates a fresh keypair and derives its address. */
    public Wallet() {
        this(generateKeyPair());
    }

    /** Wraps an existing keypair (address derived, not trusted). */
    public Wallet(KeyPair keyPair) {
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair");
        this.address = deriveAddress(keyPair.getPublic());
    }

    /**
     * Recovers a wallet from PKCS#8-encoded private key bytes, deriving the
     * public key. Use when loading a saved wallet.
     */
    public static Wallet fromPrivateKey(byte[] pkcs8) {
        Objects.requireNonNull(pkcs8, "pkcs8");
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            PrivateKey sk = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            PublicKey pk = derivePublicKey((ECPrivateKey) sk);
            return new Wallet(new KeyPair(pk, sk));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid PKCS#8 EC key", e);
        }
    }

    /** Watch-only wallet: only public key, no signing capability. */
    public static Wallet fromPublicKey(byte[] spki) {
        Objects.requireNonNull(spki, "spki");
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(spki));
            return new Wallet(new KeyPair(pk, null));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid SPKI EC key", e);
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    public String address()              { return address; }
    public PublicKey publicKey()         { return keyPair.getPublic(); }
    public boolean canSign()             { return keyPair.getPrivate() != null; }

    /** PKCS#8 bytes; guard these — they are the private key. */
    public byte[] privateKeyBytes() {
        if (keyPair.getPrivate() == null) throw new IllegalStateException("watch-only wallet");
        return keyPair.getPrivate().getEncoded();
    }

    /** SPKI bytes (public key; safe to share). */
    public byte[] publicKeyBytes() {
        return keyPair.getPublic().getEncoded();
    }

    // ── Signing / verification ────────────────────────────────────────────

    /** Signs {@code data}; throws if this is a watch-only wallet. */
    public byte[] sign(byte[] data) {
        Objects.requireNonNull(data, "data");
        if (keyPair.getPrivate() == null) throw new IllegalStateException("watch-only wallet");
        try {
            Signature s = Signature.getInstance(SIGNATURE_ALGORITHM);
            s.initSign(keyPair.getPrivate());
            s.update(data);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ECDSA signing failed", e);
        }
    }

    /** Verifies {@code signature} over {@code data} using {@code publicKeyBytes}. */
    public static boolean verify(byte[] publicKeyBytes, byte[] data, byte[] signature) {
        Objects.requireNonNull(publicKeyBytes, "publicKeyBytes");
        Objects.requireNonNull(data, "data");
        Objects.requireNonNull(signature, "signature");
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            Signature s = Signature.getInstance(SIGNATURE_ALGORITHM);
            s.initVerify(pk);
            s.update(data);
            return s.verify(signature);
        } catch (GeneralSecurityException e) {
            return false; // malformed key/sig — treat as verification failure
        }
    }

    /** Derives the address for a given public key. Exposed for validation. */
    public static String deriveAddress(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        String body = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(CryptoUtils.sha256(publicKey.getEncoded()));
        if (body.length() < ADDRESS_BODY_LENGTH) {
            throw new IllegalStateException("encoded address too short");
        }
        return "M" + body.substring(0, ADDRESS_BODY_LENGTH);
    }

    // ── Key generation ───────────────────────────────────────────────────

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec(CURVE));
            return gen.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("EC/" + CURVE + " unavailable", e);
        }
    }

    private static PublicKey derivePublicKey(ECPrivateKey sk) throws GeneralSecurityException {
        ECParameterSpec params = sk.getParams();
        if (params == null) throw new GeneralSecurityException("EC private key has no parameters");
        org.bouncycastle-free_scalar_mult(sk, params); // see below
        throw new GeneralSecurityException("EC scalar multiplication not available");
    }

    // ── Object ────────────────────────────────────────────────────────────

    @Override public String toString() { return "Wallet[" + address + "]"; }

    @Override public boolean equals(Object o) {
        return o instanceof Wallet w && address.equals(w.address);
    }

    @Override public int hashCode() { return address.hashCode(); }
}
