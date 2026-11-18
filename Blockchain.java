/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package com.mycompany.mavenproject4;

/**
 *
 * @author nadee
 */
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The chain and its consensus rules.
 *
 * <p>{@link #addBlock} validates fully (header + transactions), then commits
 * atomically: either both {@code chain} and {@code utxoSet} transition together,
 * or neither does. Concurrent calls are serialized on {@code this}.</p>
 *
 * <p>Consensus rules enforced here:</p>
 * <ul>
 *   <li>{@code previousHash} matches the current tip</li>
 *   <li>{@code hashMatchesHeader()} (hash is f(header))</li>
 *   <li>{@code meetsDifficulty()}</li>
 *   <li>{@code MiningEngine.isCombinatorialValidFromHash()} (the city puzzle)</li>
 *   <li>every transaction valid against a dry-run UTXO copy (see {@link UTXOSet#applyBlock})</li>
 * </ul>
 *
 * <p>Not thread-safe for <em>reads</em> that race with writes (you may see a
 * chain mid-transition). If you need a stable read, take {@code synchronized}
 * externally, or use {@link #snapshot()}.</p>
 */
public final class Blockchain {

    /** Fixed coinbase subsidy per block. (Height-based halving: future work.) */
    public static final long SUBSIDY = 50L;

    private final List<Block> chain = new ArrayList<>();
    private UTXOSet utxoSet = new UTXOSet();

    // ── Genesis ──────────────────────────────────────────────────────────

    /**
     * Installs a genesis block. The block must already be sealed, must have
     * {@code previousHash == ZERO_HASH}, and must pass {@code addBlock}'s rules
     * applied against an empty UTXO set.
     *
     * @throws IllegalStateException    if a genesis already exists
     * @throws IllegalArgumentException if the block is not a valid genesis
     */
    public synchronized void addGenesis(Block genesis) {
        Objects.requireNonNull(genesis, "genesis");
        if (!chain.isEmpty()) throw new IllegalStateException("genesis already exists");
        if (!genesis.isGenesis()) {
            throw new IllegalArgumentException("genesis.previousHash must be all-zero");
        }
        if (!genesis.hashMatchesHeader()) {
            throw new IllegalArgumentException("genesis hash does not match header");
        }
        if (!genesis.meetsDifficulty()) {
            throw new IllegalArgumentException("genesis does not meet its difficulty");
        }
        UTXOSet.ApplyResult r;
        try {
            r = utxoSet.applyBlock(genesis, SUBSIDY);
        } catch (UTXOSet.InvalidBlockException e) {
            throw new IllegalArgumentException("invalid genesis: " + e.getMessage(), e);
        }
        chain.add(genesis);
        utxoSet = r.newSet();
    }

    // ── Append ───────────────────────────────────────────────────────────

    /**
     * Validates and appends a block. Returns the reason on failure; the chain
     * and UTXO set are unchanged unless this returns {@link AddResult#accepted}.
     */
    public synchronized AddResult addBlock(Block candidate) {
        Objects.requireNonNull(candidate, "candidate");
        if (chain.isEmpty()) return AddResult.reject("no genesis");

        Block tip = chain.get(chain.size() - 1);

        if (!tip.hash().equals(candidate.previousHash())) {
            return AddResult.reject("previousHash does not match tip");
        }
        if (!candidate.hashMatchesHeader()) {
            return AddResult.reject("hash does not match header");
        }
        if (!candidate.meetsDifficulty()) {
            return AddResult.reject("difficulty not met");
        }
        if (!MiningEngine.isCombinatorialValidFromHash(candidate.hash())) {
            return AddResult.reject("combinatorial puzzle failed");
        }

        UTXOSet.ApplyResult r;
        try {
            r = utxoSet.applyBlock(candidate, SUBSIDY);
        } catch (UTXOSet.InvalidBlockException e) {
            return AddResult.reject("invalid transactions: " + e.getMessage());
        }

        // Commit atomically. If anything throws between these two lines, we
        // are already inside a synchronized block with a valid `r`, so this
        // cannot fail except on OOM. Assign utxoSet first (cheap) then chain.
        utxoSet = r.newSet();
        chain.add(candidate);
        return AddResult.accept(candidate.hash(), r.fees());
    }

    // ── Reads ────────────────────────────────────────────────────────────

    public synchronized int height() { return chain.size(); }
    public synchronized boolean isEmpty() { return chain.isEmpty(); }

    public synchronized Block latest() {
        if (chain.isEmpty()) throw new IllegalStateException("chain empty");
        return chain.get(chain.size() - 1);
    }

    public synchronized Optional<Block> latestIfPresent() {
        return chain.isEmpty() ? Optional.empty() : Optional.of(chain.get(chain.size() - 1));
    }

    /** Snapshot of the chain. Blocks are immutable, so this is safe to iterate. */
    public synchronized List<Block> snapshot() { return List.copyOf(chain); }

    /** Snapshot of the UTXO set. Callers can read but not mutate. */
    public synchronized UTXOSet utxoSnapshot() { return utxoSet; }

    public synchronized long balanceOf(String address) { return utxoSet.balanceOf(address); }

    // ── Chain validation ─────────────────────────────────────────────────

    /**
     * Validates a full chain from genesis, rebuilding a fresh UTXO set along
     * the way, and returns the reconstructed chain state if valid. This is what
     * {@link BlockchainStorage} calls after loading blocks from disk: never
     * trust persisted state without replaying it.
     *
     * @return a fresh {@code Blockchain} identical to what replaying {@code blocks}
     *         through {@code addGenesis}/{@code addBlock} would produce
     * @throws InvalidChainException if any block fails consensus
     */
    public static Blockchain replayAndValidate(List<Block> blocks) {
        Objects.requireNonNull(blocks, "blocks");
        if (blocks.isEmpty()) throw new InvalidChainException("empty chain");
        Blockchain bc = new Blockchain();
        try {
            bc.addGenesis(blocks.get(0));
        } catch (RuntimeException e) {
            throw new InvalidChainException("genesis invalid: " + e.getMessage(), e);
        }
        for (int i = 1; i < blocks.size(); i++) {
            AddResult r = bc.addBlock(blocks.get(i));
            if (!r.accepted()) {
                throw new InvalidChainException("block " + i + " rejected: " + r.reason());
            }
        }
        return bc;
    }

    // ── Result types ─────────────────────────────────────────────────────

    /** Outcome of {@link #addBlock}. */
    public record AddResult(boolean accepted, String reason, String hash, long fees) {
        static AddResult accept(String hash, long fees) {
            return new AddResult(true, "", hash, fees);
        }
        static AddResult reject(String reason) {
            return new AddResult(false, reason, "", 0L);
        }
    }

    /** Thrown by {@link #replayAndValidate}. */
    public static final class InvalidChainException extends RuntimeException {
        public InvalidChainException(String msg) { super(msg); }
        public InvalidChainException(String msg, Throwable cause) { super(msg, cause); }
    }
}
