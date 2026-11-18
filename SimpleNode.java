/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package com.mycompany.mavenproject4;

/**
 *
 * @author nadee
 */

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Minimal P2P node. Accepts commands, dispatches to {@link Blockchain}, and
 * returns responses. The wire protocol is length-prefixed binary (magic +
 * version + command + length-prefixed payload), not Java serialization.
 *
 * <p>Hardening:</p>
 * <ul>
 *   <li>Fixed-size worker pool (no unbounded thread creation).</li>
 *   <li>{@code Semaphore} caps concurrent connections (backpressure).</li>
 *   <li>{@code setSoTimeout} on every socket, so a peer cannot pin a thread.</li>
 *   <li>Every length is bounded before allocation; a malicious peer cannot OOM.</li>
 *   <li>Blockchain access is serialized by {@link Blockchain}'s own {@code synchronized}.</li>
 * </ul>
 *
 * <p>Not TLS and not authenticated. Fine for a LAN demo; do not expose to the
 * internet without putting it behind a TLS tunnel and an authentication layer.</p>
 */
public final class SimpleNode {

    private static final Logger LOG = Logger.getLogger(SimpleNode.class.getName());

    private static final int WORKER_THREADS = 16;
    private static final int MAX_CONCURRENT_CONNECTIONS = 64;
    private static final int SOCKET_TIMEOUT_MS = 30_000;
    private static final int MAX_PAYLOAD_BYTES = 20 * 1024 * 1024;   // 20 MB

    private static final byte[] MAGIC = "MYCOINNET\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int PROTOCOL_VERSION = 1;

    // Commands (one byte each, to stay small).
    private static final byte CMD_PING          = 0x01;
    private static final byte CMD_GET_HEIGHT    = 0x02;
    private static final byte CMD_GET_LATEST    = 0x03;
    private static final byte CMD_SUBMIT_BLOCK  = 0x04;

    // Response statuses.
    private static final byte STATUS_OK    = 0x00;
    private static final byte STATUS_ERROR = 0x01;

    private final int port;
    private final Blockchain blockchain;
    private final ExecutorService pool = Executors.newFixedThreadPool(WORKER_THREADS);
    private final Semaphore connectionPermits = new Semaphore(MAX_CONCURRENT_CONNECTIONS);
    private final AtomicBoolean stopped = new AtomicBoolean(false);

    private volatile ServerSocket serverSocket;

    public SimpleNode(int port, Blockchain blockchain) {
        this.port = port;
        this.blockchain = Objects.requireNonNull(blockchain, "blockchain");
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    /** Binds the port and starts accepting connections. Returns immediately. */
    public void start() throws IOException {
        if (serverSocket != null) throw new IllegalStateException("already started");
        ServerSocket ss = new ServerSocket(port);
        this.serverSocket = ss;
        pool.submit(() -> acceptLoop(ss));
        LOG.info("Node listening on port " + ss.getLocalPort());
    }

    /** Stops accepting and drains workers. Does not wait indefinitely. */
    public void stop() throws IOException {
        if (!stopped.compareAndSet(false, true)) return;
        ServerSocket ss = serverSocket;
        if (ss != null) ss.close();          // unblocks accept()
        pool.shutdownNow();
        try {
            pool.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public boolean isRunning() { return !stopped.get(); }

    // ── Accept loop ─────────────────────────────────────────────────────

    private void acceptLoop(ServerSocket ss) {
        while (!ss.isClosed() && !stopped.get()) {
            Socket client;
            try {
                client = ss.accept();
            } catch (SocketTimeoutException timeout) {
                continue;
            } catch (IOException e) {
                if (stopped.get() || ss.isClosed()) return;   // expected on shutdown
                LOG.log(Level.WARNING, "accept() failed", e);
                continue;
            }
            if (!connectionPermits.tryAcquire()) {
                LOG.warning("Connection rejected: at capacity");
                try { client.close(); } catch (IOException ignored) {}
                continue;
            }
            try {
                pool.submit(() -> {
                    try { handleClient(client); }
                    finally { connectionPermits.release(); }
                });
            } catch (RejectedExecutionException rejected) {
                connectionPermits.release();
                try { client.close(); } catch (IOException ignored) {}
            }
        }
    }

    // ── Per-connection handler ──────────────────────────────────────────

    private void handleClient(Socket socket) {
        try (socket) {
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            socket.setTcpNoDelay(true);
            try (InputStream is = socket.getInputStream();
                 OutputStream os = socket.getOutputStream();
                 DataInputStream in = new DataInputStream(is);
                 DataOutputStream out = new DataOutputStream(os)) {
                readAndDispatch(in, out);
                out.flush();
            }
        } catch (SocketTimeoutException e) {
            LOG.fine("connection timed out");
        } catch (IOException e) {
            LOG.log(Level.FINE, "connection I/O error", e);
        } catch (RuntimeException e) {
            // Programming error in our own code — do NOT swallow silently.
            LOG.log(Level.SEVERE, "unexpected error in handler", e);
        }
    }

    private void readAndDispatch(DataInputStream in, DataOutputStream out) throws IOException {
        byte[] magic = new byte[MAGIC.length];
        in.readFully(magic);
        if (!java.util.Arrays.equals(magic, MAGIC)) {
            writeError(out, "bad magic");
            return;
        }
        int version = in.readInt();
        if (version != PROTOCOL_VERSION) {
            writeError(out, "unsupported protocol version " + version);
            return;
        }
        byte command = in.readByte();
        switch (command) {
            case CMD_PING -> writeOkInt(out, 0);
            case CMD_GET_HEIGHT -> writeOkInt(out, blockchain.height());
            case CMD_GET_LATEST -> writeLatest(out);
            case CMD_SUBMIT_BLOCK -> handleSubmitBlock(in, out);
            default -> writeError(out, "unknown command 0x" + Integer.toHexString(command & 0xff));
        }
    }

    private void handleSubmitBlock(DataInputStream in, DataOutputStream out) throws IOException {
        Block block = readBlock(in);
        Blockchain.AddResult r = blockchain.addBlock(block);
        if (r.accepted()) {
            writeOkString(out, r.hash());
        } else {
            writeError(out, r.reason());
        }
    }

    // ── Response writers ────────────────────────────────────────────────

    private static void writeOkInt(DataOutputStream out, int value) throws IOException {
        out.writeByte(STATUS_OK);
        out.writeInt(value);
    }

    private static void writeOkString(DataOutputStream out, String value) throws IOException {
        out.writeByte(STATUS_OK);
        writeString(out, value);
    }

    private void writeLatest(DataOutputStream out) throws IOException {
        var latest = blockchain.latestIfPresent();
        if (latest.isEmpty()) { writeError(out, "no genesis"); return; }
        Block b = latest.get();
        byte[] encoded = encodeBlock(b);
        out.writeByte(STATUS_OK);
        out.writeInt(encoded.length);
        out.write(encoded);
    }

    private static void writeError(DataOutputStream out, String message) throws IOException {
        out.writeByte(STATUS_ERROR);
        writeString(out, message);
    }

    private static void writeString(DataOutputStream out, String s) throws IOException {
        byte[] bytes = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    // ── Block encoding for the wire (reuses the same fields as storage) ─

    private static byte[] encodeBlock(Block b) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bos)) {
            out.write(b.serializeHeader());   // 96 bytes
            out.writeInt(b.transactions().size());
            for (Transaction tx : b.transactions()) {
                writeTransaction(out, tx);
            }
        }
        return bos.toByteArray();
    }

    private static void writeTransaction(DataOutputStream out, Transaction tx) throws IOException {
        out.writeInt(tx.inputs().size());
        for (Transaction.Input in : tx.inputs()) {
            out.write(CryptoUtils.hexToBytes(in.prevTxId()));
            out.writeInt(in.outputIndex());
            writeVar(out, in.signature());
            writeVar(out, in.publicKey());
        }
        out.writeInt(tx.outputs().size());
        for (Transaction.Output o : tx.outputs()) {
            out.writeLong(o.amount());
            writeVar(out, o.address().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        out.writeLong(tx.lockTime());
    }

    private static void writeVar(DataOutputStream out, byte[] b) throws IOException {
        out.writeInt(b.length);
        out.write(b);
    }

    private static Block readBlock(DataInputStream in) throws IOException {
        byte[] header = new byte[96];
        in.readFully(header);
        int version    = readIntLE(header, 0);
        if (version != Block.VERSION) throw new IOException("bad block version");
        String prevHash = bytesToHex(header, 4, 32);
        String merkleOnDisk = bytesToHex(header, 36, 32);
        long timestamp  = readLongLE(header, 68);
        long difficulty = readLongLE(header, 76);
        long nonce      = readLongLE(header, 84);
        int citySeed    = readIntLE(header, 92);

        int txCount = readBoundedInt(in, "tx count", 100_000);
        List<Transaction> txs = new java.util.ArrayList<>(txCount);
        for (int i = 0; i < txCount; i++) {
            txs.add(readTransaction(in));
        }
        Block rebuilt = Block.seal(prevHash, timestamp, difficulty, nonce, citySeed, txs);
        if (!rebuilt.merkleRoot().equals(merkleOnDisk)) {
            throw new IOException("block merkleRoot does not match transactions");
        }
        return rebuilt;
    }

    private static Transaction readTransaction(DataInputStream in) throws IOException {
        int inCount = readBoundedInt(in, "input count", 100_000);
        List<Transaction.Input> inputs = new java.util.ArrayList<>(inCount);
        for (int i = 0; i < inCount; i++) {
            byte[] prev = new byte[32];
            in.readFully(prev);
            int outputIndex = in.readInt();
            byte[] sig = readVar(in);
            byte[] pub = readVar(in);
            inputs.add(new Transaction.Input(bytesToHex(prev, 0, 32), outputIndex, sig, pub));
        }
        int outCount = readBoundedInt(in, "output count", 100_000);
        List<Transaction.Output> outputs = new java.util.ArrayList<>(outCount);
        for (int i = 0; i < outCount; i++) {
            long amount = in.readLong();
            byte[] addr = readVar(in);
            outputs.add(new Transaction.Output(amount,
                    new String(addr, java.nio.charset.StandardCharsets.UTF_8)));
        }
        long lockTime = in.readLong();
        if (inputs.isEmpty()) return Transaction.coinbase(outputs.get(0).address(), outputs.get(0).amount());
        return Transaction.create(inputs, outputs, lockTime);
    }

    private static byte[] readVar(DataInputStream in) throws IOException {
        int len = readBoundedInt(in, "field length", MAX_PAYLOAD_BYTES);
        byte[] buf = new byte[len];
        in.readFully(buf);
        return buf;
    }

    private static int readBoundedInt(DataInputStream in, String what, int max) throws IOException {
        int n = in.readInt();
        if (n < 0 || n > max) throw new IOException(what + " out of range: " + n);
        return n;
    }

    private static int readIntLE(byte[] b, int off) {
        return  (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
             | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }

    private static long readLongLE(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) v |= (long) (b[off + i
