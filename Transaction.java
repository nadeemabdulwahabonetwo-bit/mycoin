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
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

/**
 * A MyCoin transaction. Immutable once constructed.
 *
 * <p>The {@code txId} is a double-SHA-256 of a canonical, unambiguous byte
 * encoding of the transaction's contents. This is what makes a block's merkle
 * root (and therefore the block hash) commit to the transactions it contains.</p>
 */
public final class Transaction {

    public static final int TXID_BYTES = 32;
    public static final int SIGHASH_BYTES = 32;

    // ── Nested types ──────────────────────────────────────────────────────

    /**
     * A reference to a previous output, plus the signature authorising the spend.
     * Empty signature/publicKey marks a coinbase input (only present inside
     * coinbase transactions, which we model with no inputs — see {@link #coinbase}).
     */
    public record Input(String prevTxId, int outputIndex, byte[] signature, byte[] publicKey) {

        public Input {
            Objects.requireNonNull(prevTxId, "prevTxId");
            if (prevTxId.length() != TXID_BYTES * 2) {
                throw new IllegalArgumentException("prevTxId must be 64 hex chars");
            }
            if (outputIndex < 0) throw new IllegalArgumentException("outputIndex < 0");
            Objects.requireNonNull(signature, "signature");
            Objects.requireNonNull(publicKey, "publicKey");
            signature = signature.clone();
            publicKey = publicKey.clone();
        }

        @Override public byte[] signature() { return signature.clone(); }
        @Override public byte[] publicKey() { return publicKey.clone(); }
    }

    public record Output(long amount, String address) {
        public Output {
            if (amount <= 0) throw new IllegalArgumentException("amount must be > 0");
            Objects.requireNonNull(address, "address");
            if (address.isEmpty()) throw new IllegalArgumentException("address empty");
        }
    }

    // ── Fields ────────────────────────────────────────────────────────────

    private final String txId;          // hex, 64 chars
    private final List<Input> inputs;   // immutable
    private final List<Output> outputs; // immutable
    private final long lockTime;

    private Transaction(String txId, List<Input> inputs, List<Output> outputs, long lockTime) {
        this.txId = txId;
        this.inputs = List.copyOf(inputs);
        this.outputs = List.copyOf(outputs);
        this.lockTime = lockTime;
    }

    // ── Constructors / factories ─────────────────────────────────────────

    /** Builds a regular transaction and derives its txId from the contents. */
    public static Transaction create(List<Input> inputs, List<Output> outputs, long lockTime) {
        Objects.requireNonNull(inputs, "inputs");
        Objects.requireNonNull(outputs, "outputs");
        if (inputs.isEmpty()) throw new IllegalArgumentException("use coinbase() for no inputs");
        if (outputs.isEmpty()) throw new IllegalArgumentException("must have at least one output");
        Transaction bare = new Transaction("", inputs, outputs, lockTime);
        String id = CryptoUtils.doubleSha256Hex(bare.canonicalBytes());
        return new Transaction(id, inputs, outputs, lockTime);
    }

    /** Builds a coinbase transaction (no inputs) paying {@code reward} to {@code minerAddress}. */
    public static Transaction coinbase(String minerAddress, long reward) {
        Objects.requireNonNull(minerAddress, "minerAddress");
        if (reward <= 0) throw new IllegalArgumentException("reward must be > 0");
        List<Input> noInputs = List.of();
        List<Output> outs = List.of(new Output(reward, minerAddress));
        // Coinbase txId: hash of outputs + lockTime + a marker distinguishing coinbase.
        Transaction bare = new Transaction("", noInputs, outs, 0L);
        String id = CryptoUtils.doubleSha256Hex(bare.canonicalBytes());
        return new Transaction(id, noInputs, outs, 0L);
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    public String txId()          { return txId; }
    public List<Input> inputs()   { return inputs; }
    public List<Output> outputs() { return outputs; }
    public long lockTime()        { return lockTime; }
    public boolean isCoinbase()   { return inputs.isEmpty(); }

    // ── Canonical encoding ────────────────────────────────────────────────

    /**
     * Deterministic, unambiguous bytes used for {@code txId} and (in Phase 2)
     * for signatures. Every variable-length field is length-prefixed; every
     * fixed-size field is written at its natural width, little-endian
     * (Bitcoin-style). Two different transactions cannot produce the same bytes.
     *
     * <p>Signatures and public keys are intentionally excluded from the txId
     * (they are added after the id is derived). Phase 2 will add a
     * {@link #sighash()} that includes what must be signed but not the
     * signature itself.</p>
     */
    public byte[] canonicalBytes() {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(128);
            out.write(0x01); // version marker for this encoding, so it can evolve

            writeUInt32(out, inputs.size());
            for (Input in : inputs) {
                byte[] prev = CryptoUtils.hexToBytes(in.prevTxId());
                out.write(prev);
                writeUInt32(out, in.outputIndex());
            }

            writeUInt32(out, outputs.size());
            for (Output o : outputs) {
                writeUInt64(out, o.amount());
                writeVarBytes(out, o.address().getBytes(StandardCharsets.UTF_8));
            }

            writeUInt64(out, lockTime);
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("in-memory write failed", e);
        }
    }

    /**
     * Bytes that a signature over this input must commit to. Phase 2 fills this in;
     * for now it includes the canonical transaction body plus the input's outpoint
     * so signatures are per-input.
     */
    public byte[] sighash(int inputIndex) {
        if (inputIndex < 0 || inputIndex >= inputs.size()) {
            throw new IndexOutOfBoundsException("inputIndex " + inputIndex);
        }
        Input in = inputs.get(inputIndex);
        byte[] body = canonicalBytes();
        byte[] outpoint = new byte[TXID_BYTES + 4];
        System.arraycopy(CryptoUtils.hexToBytes(in.prevTxId()), 0, outpoint, 0, TXID_BYTES);
        ByteBuffer.wrap(outpoint, TXID_BYTES, 4).putInt(in.outputIndex());
        byte[] combined = new byte[body.length + outpoint.length + 4];
        System.arraycopy(body, 0, combined, 0, body.length);
        System.arraycopy(outpoint, 0, combined, body.length, outpoint.length);
        ByteBuffer.wrap(combined, body.length + outpoint.length, 4).putInt(inputIndex);
        return CryptoUtils.doubleSha256(combined);
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    private static void writeUInt32(ByteArrayOutputStream out, int v) {
        out.write(v & 0xff); out.write((v >>> 8) & 0xff);
        out.write((v >>> 16) & 0xff); out.write((v >>> 24) & 0xff);
    }

    private static void writeUInt64(ByteArrayOutputStream out, long v) {
        for (int i = 0; i < 8; i++) out.write((int) ((v >>> (8 * i)) & 0xff));
    }

    private static void writeVarBytes(ByteArrayOutputStream out, byte[] b) {
        writeUInt32(out, b.length);
        out.writeBytes(b);
    }

    // ── Object ────────────────────────────────────────────────────────────

    @Override public String toString() {
        return "Transaction[" + txId + ", in=" + inputs.size()
             + ", out=" + outputs.size() + ", coinbase=" + isCoinbase() + "]";
    }

    @Override public boolean equals(Object o) {
        return o instanceof Transaction t && txId.equals(t.txId);
    }

    @Override public int hashCode() { return txId.hashCode(); }
}
