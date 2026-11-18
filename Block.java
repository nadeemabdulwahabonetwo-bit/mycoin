/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package com.mycompany.mavenproject4;

/**
 *
 * @author nadee
 */
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A MyCoin block. Immutable once constructed.
 *
 * <p>The hash commits to the fixed-width header and, via the merkle root, to
 * every transaction in the block. Tampering with any transaction changes the
 * merkle root, which changes the block hash.</p>
 */
public final class Block {

    public static final int VERSION = 1;
    public static final int HASH_HEX_LEN = 64;
    public static final String ZERO_HASH = "0".repeat(HASH_HEX_LEN);

    private final int version;
    private final String previousHash;
    private final String merkleRoot;
    private final long timestamp;
    private final long difficultyTarget;   // count of leading zero hex digits required
    private final long nonce;
    private final int citySeed;
    private final List<Transaction> transactions;
    private final String hash;             // hex of double-SHA-256(header)

    private Block(int version, String previousHash, String merkleRoot, long timestamp,
                  long difficultyTarget, long nonce, int citySeed,
                  List<Transaction> transactions, String hash) {
        this.version = version;
        this.previousHash = previousHash;
        this.merkleRoot = merkleRoot;
        this.timestamp = timestamp;
        this.difficultyTarget = difficultyTarget;
        this.nonce = nonce;
        this.citySeed = citySeed;
        this.transactions = List.copyOf(transactions);
        this.hash = hash;
    }

    // ── Factory ───────────────────────────────────────────────────────────

    /**
     * Builds a block from a template, computing the merkle root and the block hash.
     * This is the only way to produce a {@code Block}; the result is immutable and
     * safe to store in a chain or send over a network.
     *
     * @param previousHash 64 hex chars, or {@link #ZERO_HASH} for genesis
     * @param difficultyTarget number of leading hex zeros required (0..64)
     * @param transactions  immutable copy taken
     */
    public static Block seal(String previousHash, long timestamp, long difficultyTarget,
                             long nonce, int citySeed, List<Transaction> transactions) {
        Objects.requireNonNull(previousHash, "previousHash");
        if (previousHash.length() != HASH_HEX_LEN) {
            throw new IllegalArgumentException("previousHash must be 64 hex chars");
        }
        if (difficultyTarget < 0 || difficultyTarget > HASH_HEX_LEN) {
            throw new IllegalArgumentException("difficultyTarget must be in [0, 64]");
        }
        Objects.requireNonNull(transactions, "transactions");
        List<Transaction> txs = List.copyOf(transactions);

        String merkleRoot = computeMerkleRoot(txs);
        Block unhashed = new Block(VERSION, previousHash, merkleRoot, timestamp,
                                   difficultyTarget, nonce, citySeed, txs, "");
        String hash = CryptoUtils.doubleSha256Hex(unhashed.serializeHeader());
        return new Block(VERSION, previousHash, merkleRoot, timestamp,
                         difficultyTarget, nonce, citySeed, txs, hash);
    }

    /** Convenience: genesis block (previousHash is the all-zero string). */
    public static Block genesis(long timestamp, long difficultyTarget, int citySeed,
                                List<Transaction> transactions) {
        return seal(ZERO_HASH, timestamp, difficultyTarget, 0L, citySeed, transactions);
    }

    /**
     * Returns a copy with the given nonce (used by {@link MiningEngine}).
     * Kept here so mining cannot bypass the invariant that hash = f(header).
     */
    public Block withNonceAndSeed(long newNonce, int newCitySeed) {
        return seal(previousHash, timestamp, difficultyTarget, newNonce, newCitySeed, transactions);
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    public int version()              { return version; }
    public String previousHash()      { return previousHash; }
    public String merkleRoot()        { return merkleRoot; }
    public long timestamp()           { return timestamp; }
    public long difficultyTarget()    { return difficultyTarget; }
    public long nonce()               { return nonce; }
    public int citySeed()             { return citySeed; }
    public List<Transaction> transactions() { return transactions; }
    public String hash()              { return hash; }
    public boolean isGenesis()        { return previousHash.equals(ZERO_HASH); }

    // ── Consensus checks ──────────────────────────────────────────────────

    /** True if the hash has at least {@link #difficultyTarget()} leading hex zeros. */
    public boolean meetsDifficulty() {
        if (hash.isEmpty()) throw new IllegalStateException("hash not computed");
        long required = Math.min(difficultyTarget, HASH_HEX_LEN);
        if (required == 0) return true;
        for (int i = 0; i < required; i++) {
            if (hash.charAt(i) != '0') return false;
        }
        return true;
    }

    /** True if this block's recomputed header hash equals its stored hash. */
    public boolean hashMatchesHeader() {
        return hash.equals(CryptoUtils.doubleSha256Hex(serializeHeader()));
    }

    // ── Header serialization (canonical, fixed-width) ─────────────────────

    /**
     * Fixed-width binary header, little-endian. Total size is constant:
     * 4 (version) + 32 (previousHash) + 32 (merkleRoot)
     * + 8 (timestamp) + 8 (difficultyTarget) + 8 (nonce) + 4 (citySeed) = 96 bytes.
     *
     * <p>Every field occupies its natural width, so no two distinct headers can
     * produce the same bytes. This is the fix for the original
     * {@code StringBuilder.append(...)} encoding, which was ambiguous.</p>
     */
    public byte[] serializeHeader() {
        ByteBuffer buf = ByteBuffer.allocate(96).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(version);
        buf.put(CryptoUtils.hexToBytes(previousHash));
        buf.put(CryptoUtils.hexToBytes(merkleRoot));
        buf.putLong(timestamp);
        buf.putLong(difficultyTarget);
        buf.putLong(nonce);
        buf.putInt(citySeed);
        return buf.array();
    }

    // ── Merkle root ───────────────────────────────────────────────────────

    /**
     * Bitcoin-style merkle root over the transactions' txIds.
     * Empty block → 32 zero bytes (as hex). Single-tx → that txId.
     * Odd count at any level → the last hash is duplicated.
     */
    public static String computeMerkleRoot(List<Transaction> txs) {
        Objects.requireNonNull(txs, "txs");
        if (txs.isEmpty()) return ZERO_HASH;
        List<byte[]> level = new ArrayList<>(txs.size());
        for (Transaction t : txs) level.add(CryptoUtils.hexToBytes(t.txId()));
        while (level.size() > 1) {
            List<byte[]> next = new ArrayList<>((level.size() + 1) / 2);
            for (int i = 0; i < level.size(); i += 2) {
                byte[] left = level.get(i);
                byte[] right = (i + 1 < level.size()) ? level.get(i + 1) : left;
                byte[] pair = new byte[left.length + right.length];
                System.arraycopy(left, 0, pair, 0, left.length);
                System.arraycopy(right, 0, pair, left.length, right.length);
                next.add(CryptoUtils.doubleSha256(pair));
            }
            level = next;
        }
        return CryptoUtils.bytesToHex(level.get(0));
    }

    // ── Object ────────────────────────────────────────────────────────────

    @Override public String toString() {
        return "Block[" + hash.substring(0, 16) + "…, prev="
             + previousHash.substring(0, 16) + "…, txs=" + transactions.size() + "]";
    }

    @Override public boolean equals(Object o) {
        return o instanceof Block b && hash.equals(b.hash);
    }

    @Override public int hashCode() { return hash.hashCode(); }
}
