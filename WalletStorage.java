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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;

/**
 * Saves and loads a {@link Wallet} as two length-prefixed blobs (PKCS#8 private
 * key + SPKI public key) with a magic header and version.
 *
 * <p>This is <b>not</b> encryption. The file contains the private key in the
 * clear. It is the caller's responsibility to protect the directory. For a
 * production wallet, replace this with PKCS#12 / an OS keychain — but never
 * with Java serialization (see {@code BlockchainStorage} for why).</p>
 */
public final class WalletStorage {

    private static final byte[] MAGIC = "MYCOINWALLET\0".getBytes(StandardCharsets.US_ASCII);
    private static final int FORMAT_VERSION = 1;
    private static final int MAX_KEY_BYTES = 1024;   // PKCS#8/SPKI EC keys are ~ 120 bytes

    private final Path file;

    public WalletStorage(String path) {
        this.file = Paths.get(path);
    }

    /** Saves atomically (tmp + replace). */
    public void save(Wallet wallet) throws IOException {
        if (!wallet.canSign()) {
            throw new IOException("cannot save watch-only wallet");
        }
        Path tmp = Files.createTempFile(file.toAbsolutePath().getParent(), "wallet", ".tmp");
        try {
            try (OutputStream os = Files.newOutputStream(tmp)) {
                try (DataOutputStream out = new DataOutputStream(os)) {
                    out.write(MAGIC);
                    out.writeInt(FORMAT_VERSION);
                    writeVarBytes(out, wallet.privateKeyBytes());
                    writeVarBytes(out, wallet.publicKeyBytes());
                }
            }
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicFailed) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /** Loads a wallet, validating that private and public halves match. */
    public Wallet load() throws IOException {
        if (!Files.exists(file)) throw new IOException("wallet file not found: " + file);
        try (InputStream is = Files.newInputStream(file)) {
            try (DataInputStream in = new DataInputStream(is)) {
                byte[] magic = new byte[MAGIC.length];
                in.readFully(magic);
                if (!Arrays.equals(magic, MAGIC)) throw new IOException("bad wallet magic");
                int version = in.readInt();
                if (version != FORMAT_VERSION) {
                    throw new IOException("unsupported wallet version: " + version);
                }
                byte[] pkcs8 = readVarBytes(in);
                byte[] spki  = readVarBytes(in);
                return Wallet.fromKeyPairBytes(pkcs8, spki);
            }
        }
    }

    private static void writeVarBytes(DataOutputStream out, byte[] b) throws IOException {
        if (b.length > MAX_KEY_BYTES) throw new IOException("key too large: " + b.length);
        out.writeInt(b.length);
        out.write(b);
    }

    private static byte[] readVarBytes(DataInputStream in) throws IOException {
        int len = in.readInt();
        if (len < 0 || len > MAX_KEY_BYTES) throw new IOException("bad field length: " + len);
        byte[] buf = new byte[len];
        in.readFully(buf);
        return buf;
    }
}
