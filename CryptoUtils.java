/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package com.mycompany.mavenproject4;

/**
 *
 * @author nadee
 */


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * SHA-256 hashing and hex encoding. This class is the cryptographic trust root of
 * the project: every txId, merkle root, block hash, and address flows through
 * {@link #sha256(byte[])}. A bug here compromises everything.
 *
 * <p>Instances are stateless; all methods are thread-safe.</p>
 */
public final class CryptoUtils {

    /** Hex formatter (lowercase, matching Bitcoin/display conventions). */
    private static final HexFormat HEX = HexFormat.of().withLowerCase();

    private CryptoUtils() {}

    /** SHA-256 of {@code input}. Returns a fresh 32-byte array. */
    public static byte[] sha256(byte[] input) {
        Objects.requireNonNull(input, "input");
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory in every conformant JVM.
            throw new IllegalStateException("SHA-256 unavailable in this JVM", e);
        }
    }

    /** SHA-256 applied twice (Bitcoin-style; resists length-extension attacks). */
    public static byte[] doubleSha256(byte[] input) {
        return sha256(sha256(input));
    }

    /** Lowercase hex of the given bytes. */
    public static String bytesToHex(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        return HEX.formatHex(bytes);
    }

    /**
     * Parses lowercase or uppercase hex.
     *
     * @throws IllegalArgumentException if {@code hex} is odd-length or not valid hex
     */
    public static byte[] hexToBytes(String hex) {
        Objects.requireNonNull(hex, "hex");
        return HEX.parseHex(hex);
    }

    /** Convenience: {@code sha256Hex(bytes)} = hex of {@code sha256(bytes)}. */
    public static String sha256Hex(byte[] bytes) {
        return bytesToHex(sha256(bytes));
    }

    /** Convenience: hash a UTF-8 string. */
    public static String sha256Hex(String text) {
        Objects.requireNonNull(text, "text");
        return bytesToHex(sha256(text.getBytes(StandardCharsets.UTF_8)));
    }

    /** Convenience: double-SHA-256 then hex — the standard txId/merkle building block. */
    public static String doubleSha256Hex(byte[] bytes) {
        return bytesToHex(doubleSha256(bytes));
    }
}