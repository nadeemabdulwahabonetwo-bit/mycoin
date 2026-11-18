/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package com.mycompany.mavenproject4;

/**
 *
 * @author nadee
 */
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Finds a nonce + citySeed producing a hash that satisfies both the difficulty
 * target and the combinatorial puzzle. Stateless: safe to call from any thread,
 * and safe to instantiate many times.
 *
 * <p>Two modes:</p>
 * <ul>
 *   <li>{@link #mine(Block, long)} — random {@code citySeed} per attempt. Fast,
 *       non-deterministic. Good for a live miner.</li>
 *   <li>{@link #mineDeterministic(Block, long)} — {@code citySeed} derived from
 *       {@code nonce}. Reproducible; good for tests and re-mining.</li>
 * </ul>
 */
public final class MiningEngine {

    public static final int MIN_DISTANCE = 1;
    public static final int MAX_DISTANCE = 50;   // inclusive (see span computation)

    /** Result of a mining attempt. {@code mined} is non-null iff successful. */
    public record MiningResult(boolean success, long attempts, Block mined) {
        public static MiningResult fail(long attempts) {
            return new MiningResult(false, attempts, null);
        }
        public static MiningResult ok(long attempts, Block mined) {
            return new MiningResult(true, attempts, mined);
        }
    }

    private MiningEngine() {}

    // ── Public entry points ──────────────────────────────────────────────

    /** Random citySeed per attempt. */
    public static MiningResult mine(Block template, long maxAttempts) {
        Objects.requireNonNull(template, "template");
        if (maxAttempts < 0) throw new IllegalArgumentException("maxAttempts < 0");
        ThreadLocalRandom rnd = ThreadLocalRandom.current();
        return doMine(template, maxAttempts, n -> rnd.nextInt());
    }

    /** Deterministic citySeed derived from nonce. */
    public static MiningResult mineDeterministic(Block template, long maxAttempts) {
        Objects.requireNonNull(template, "template");
        if (maxAttempts < 0) throw new IllegalArgumentException("maxAttempts < 0");
        return doMine(template, maxAttempts, MiningEngine::mixCitySeed);
    }

    // ── Core loop ────────────────────────────────────────────────────────

    private interface SeedFn { int apply(long nonce); }

    private static MiningResult doMine(Block template, long maxAttempts, SeedFn seedFn) {
        Block current = template;
        for (long attempt = 1; attempt <= maxAttempts; attempt++) {
            current = template.withNonceAndSeed(attempt, seedFn.apply(attempt));

            if (!current.meetsDifficulty()) continue;
            if (!isCombinatorialValidFromHash(current.hash())) continue;
            return MiningResult.ok(attempt, current);
        }
        return MiningResult.fail(maxAttempts);
    }

    // ── Combinatorial puzzle (public so Blockchain can re-verify) ────────

    /**
     * Extracts one distance per city from the first {@code TOTAL_CITIES} bytes
     * of the hash, in {@code [MIN_DISTANCE, MAX_DISTANCE]} inclusive.
     */
    static int[] extractDistances(String hashHex) {
        Objects.requireNonNull(hashHex, "hashHex");
        if (hashHex.length() != Block.HASH_HEX_LEN) {
            throw new IllegalArgumentException("hash must be 64 hex chars");
        }
        byte[] bytes = CryptoUtils.hexToBytes(hashHex);
        int span = MAX_DISTANCE - MIN_DISTANCE + 1;
        int[] out = new int[CityUtils.TOTAL_CITIES];
        for (int i = 0; i < out.length; i++) {
            out[i] = (Byte.toUnsignedInt(bytes[i]) % span) + MIN_DISTANCE;
        }
        return out;
    }

    /**
     * The "combinatorial validity" rule: all city combination values are
     * positive and their sum is even.
     *
     * <p>Recomputes both distances and combinations from the hash, so a caller
     * cannot feed it pre-computed values that disagree with the hash.</p>
     */
    public static boolean isCombinatorialValidFromHash(String hashHex) {
        int[] distances = extractDistances(hashHex);
        long[] results = CityUtils.calculateCityResults(distances);
        long sum = 0;
        for (long r : results) {
            if (r <= 0) return false;
            sum += r;
        }
        return (sum & 1L) == 0L;
    }

    // ── Deterministic seed mixing ────────────────────────────────────────

    /**
     * SplitMix64 finalizer truncated to int. Not cryptographic, but it makes
     * "nonce N always yields citySeed S" true across runs and platforms.
     */
    private static int mixCitySeed(long nonce) {
        long z = nonce + 0x9E3779B97F4A7C15L;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        z = z ^ (z >>> 31);
        return (int) z;
    }
}
