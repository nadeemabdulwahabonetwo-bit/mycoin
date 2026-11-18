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
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Persists a {@link Blockchain} to disk and reloads it.
 *
 * <p>Format: see the comment block at the top of the class (binary, versioned,
 * length-prefixed). Blocks are stored by <em>content</em> (header + tx data);
 * {@code hash} and {@code merkleRoot} are recomputed on load, so a tampered
 * file fails {@link Blockchain#replayAndValidate(List)} — the chain is
 * self-verifying, not blindly trusted.</p>
 *
 * <p>Writes are atomic: the new file is written to a temporary sibling and
 * moved into place with {@code ATOMIC_MOVE} (with a non-atomic fallback for
 * filesystems that refuse it). A crash mid-write leaves the old file intact.</p>
 *
 * <p>The UTXO set is <b>not</b> persisted. It is reconstructed by replaying
 * the chain on load, which is the only way to guarantee it matches the chain.</p>
 */
public final class BlockchainStorage {

    private static final byte[] MAGIC = "MYCOINCHAIN\0".getBytes(StandardCharsets.US_ASCII);
    private static final int FORMAT_VERSION = 1;
    private static final int MAX_BLOCK_COUNT = 10_000_000;
    private static final int MAX_TX_PER_BLOCK = 1_000_000;
    private static final int MAX_INPUTS_PER_TX = 100_000;
    private static final int MAX_OUTPUTS_PER_TX = 100_000;
    private static final int MAX_VAR_FIELD_LEN = 10 * 1024 * 1024;   // 10 MB

    private final Path dataDir;
    private final Path chainFile;

    public BlockchainStorage(String directory) throws IOException {
        this.dataDir = Paths.get(directory).toAbsolutePath();
        Files.createDirectories(dataDir);
        this.chainFile = dataDir.resolve("chain.bin");
    }

    // ── Save ────────────────────────────────────────────────────────────

    /**
     * Saves the chain atomically. Reads a snapshot from the blockchain (which
     * returns immutable blocks), so concurrent appends during a save are
     * either fully included or fully absent.
     */
    public void save(Blockchain blockchain) throws IOException {
        List<Block> snapshot = blockchain.snapshot();
        Path tmp = Files.createTempFile(dataDir, "chain", ".tmp");
        try {
            try (OutputStream os = Files.newOutputStream(tmp)) {
                writeChain(os, snapshot);
            }
            try {
                Files.move(tmp, chainFile,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicFailed) {
                // Some filesystems don't support ATOMIC_MOVE. Fall back to a
                // non-atomic replace. Data is still on disk and correct; only
                // power-loss durability is weaker.
                Files.move(tmp, chainFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    // ── Load ────────────────────────────────────────────────────────────

    /**
     * Loads and <b>fully validates</b> the chain from disk by replaying every
     * block through the consensus rules. Returns a fresh, valid {@link Blockchain}
     * (with a rebuilt UTXO set), or throws.
     *
     * @throws IOException on I/O or format errors
     * @throws Blockchain.InvalidChainException if a block fails consensus
     *         (i.e., the file was tampered with or written by an incompatible
     *         version)
     */
    public Blockchain load() throws IOException {
        if (!Files.exists(chainFile)) {
            throw new IOException("chain file not found: " + chainFile);
        }
        List<Block> blocks;
        try (InputStream is = Files.newInputStream(chainFile)) {
            blocks = readChain(is);
        }
        return Blockchain.replayAndValidate(blocks);
    }

    /** True if a chain file already exists (fresh-node check). */
    public boolean exists() {
        return Files.exists(chainFile);
    }

    // ── Serialization (write) ───────────────────────────────────────────

    private static void writeChain(OutputStream os, List<Block> chain) throws IOException {
        if (chain.size() > MAX_BLOCK_COUNT) {
            throw new IOException("chain too large: " + chain.size());
        }
        try (DataOutputStream out = new DataOutputStream(os)) {
            out.write(MAGIC);
            out.writeInt(FORMAT_VERSION);
            out.writeInt(chain.size());
            for (Block b : chain) {
                writeBlock(out, b);
            }
        }
    }

    private static void writeBlock(DataOutputStream out, Block b) throws IOException {
        if (b.transactions().size() > MAX_TX_PER_BLOCK) {
            throw new IOException("too many txs in block: " + b.transactions().size());
        }
        out.write(b.serializeHeader());               // 96 bytes, canonical
        out.writeInt(b.transactions().size());
        for (Transaction tx : b.transactions()) {
            writeTransaction(out, tx);
        }
    }

    private static void writeTransaction(DataOutputStream out, Transaction tx) throws IOException {
        if (tx.inputs().size() > MAX_INPUTS_PER_TX
                || tx.outputs().size() > MAX_OUTPUTS_PER_TX) {
            throw new IOException("tx too large: in=" + tx.inputs().size()
                    + " out=" + tx.outputs().size());
        }
        out.writeInt(tx.inputs().size());
        for (Transaction.Input in : tx.inputs()) {
            out.write(CryptoUtils.hexToBytes(in.prevTxId()));   // 32 bytes
            out.writeInt(in.outputIndex());
            writeVarBytes(out, in.signature());
            writeVarBytes(out, in.publicKey());
        }
        out.writeInt(tx.outputs().size());
        for (Transaction.Output o : tx.outputs()) {
            out.writeLong(o.amount());
            writeVarBytes(out, o.address().getBytes(StandardCharsets.UTF_8));
        }
        out.writeLong(tx.lockTime());
    }

    private static void writeVarBytes(DataOutputStream out, byte[] bytes) throws IOException {
        if (bytes.length > MAX_VAR_FIELD_LEN) {
            throw new IOException("field too large: " + bytes.length);
        }
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    // ── Deserialization (read) ──────────────────────────────────────────

    private static List<Block> readChain(InputStream is) throws IOException {
        try (DataInputStream in = new DataInputStream(is)) {
            byte[] magic = new byte[MAGIC.length];
            in.readFully(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new IOException("not a MyCoin chain file (bad magic)");
            }
            int version = in.readInt();
            if (version != FORMAT_VERSION) {
                throw new IOException("unsupported chain format version: " + version);
            }
            int count = readBoundedInt(in, "block count", MAX_BLOCK_COUNT);
            List<Block> blocks = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                blocks.add(readBlock(in));
            }
            return blocks;
        } catch (EOFException e) {
            throw new IOException("chain file is truncated (unexpected end of file)", e);
        }
    }

    private static Block readBlock(DataInputStream in) throws IOException {
        byte[] header = new byte[96];
        in.readFully(header);
        // Reconstruct header fields from the 96-byte header. We deliberately
        // don't trust a stored hash/merkleRoot — we recompute them via seal().
        int version = readIntLE(header, 0);
        if (version != Block.VERSION) {
            throw new IOException("unsupported block version: " + version);
        }
        String previousHash = bytesToHex(header, 4, 32);
        String merkleRootOnDisk = bytesToHex(header, 36, 32);   // informational
        long timestamp      = readLongLE(header, 68);
        long difficulty     = readLongLE(header, 76);
        long nonce          = readLongLE(header, 84);
        int citySeed        = readIntLE(header, 92);

        int txCount = readBoundedInt(in, "tx count", MAX_TX_PER_BLOCK);
        List<Transaction> txs = new ArrayList<>(txCount);
        for (int i = 0; i < txCount; i++) {
            txs.add(readTransaction(in));
        }

        // Rebuild the block deterministically. This recomputes merkleRoot and hash
        // from contents. If the on-disk merkleRoot differs, the header was tampered
        // with; we detect it here rather than in Blockchain.replayAndValidate, so
        // the error message is more specific.
        Block rebuilt = Block.seal(previousHash, timestamp, difficulty, nonce, citySeed, txs);
        if (!rebuilt.merkleRoot().equals(merkleRootOnDisk)) {
            throw new IOException("block header merkleRoot does not match transactions");
        }
        return rebuilt;
    }

    private static Transaction readTransaction(DataInputStream in) throws IOException {
        int inCount = readBoundedInt(in, "input count", MAX_INPUTS_PER_TX);
        List<Transaction.Input> inputs = new ArrayList<>(inCount);
        for (int i = 0; i < inCount; i++) {
            byte[] prevTxIdBytes = new byte[32];
            in.readFully(prevTxIdBytes);
            int outputIndex = in.readInt();
            byte[] sig = readVarBytes(in);
            byte[] pub = readVarBytes(in);
            inputs.add(new Transaction.Input(bytesToHex(prevTxIdBytes), outputIndex, sig, pub));
        }
        int outCount = readBoundedInt(in, "output count", MAX_OUTPUTS_PER_TX);
        List<Transaction.Output> outputs = new ArrayList<>(outCount);
        for (int i = 0; i < outCount; i++) {
            long amount = in.readLong();
            byte[] addrBytes = readVarBytes(in);
            outputs.add(new Transaction.Output(amount,
                    new String(addrBytes, StandardCharsets.UTF_8)));
        }
        long lockTime = in.readLong();

        if (inputs.isEmpty()) {
            if (outputs.size() != 1) {
                throw new IOException("coinbase must have exactly one output");
            }
            return Transaction.coinbase(outputs.get(0).address(), outputs.get(0).amount());
        }
        return Transaction.create(inputs, outputs, lockTime);
    }

    private static byte[] readVarBytes(DataInputStream in) throws IOException {
        int len = readBoundedInt(in, "field length", MAX_VAR_FIELD_LEN);
        byte[] buf = new byte[len];
        in.readFully(buf);
        return buf;
    }

    private static int readBoundedInt(DataInputStream in, String what, int max) throws IOException {
        int n = in.readInt();
        if (n < 0 || n > max) {
            throw new IOException(what + " out of range: " + n);
        }
        return n;
    }

    // ── Little-endian helpers (match Block.serializeHeader) ─────────────

    private static int readIntLE(byte[] buf, int off) {
        return  (buf[off] & 0xff)
             | ((buf[off + 1] & 0xff) << 8)
             | ((buf[off + 2] & 0xff) << 16)
             | ((buf[off + 3] & 0xff) << 24);
    }

    private static long readLongLE(byte[] buf, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) v |= (long) (buf[off + i] & 0xff) << (8 * i);
        return v;
    }

    private static String bytesToHex(byte[] bytes, int offset, int length) {
        return CryptoUtils.bytesToHex(Arrays.copyOfRange(bytes, offset, offset + length));
    }
}
