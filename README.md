# ChaCha-VR
ChaCha-Variable, Proof of concept. Why? I dont know, i was bored.

# ChaCha-VR (Variable Rounds) — PoC

**ChaCha-VR (Variable Rounds)** is a proof-of-concept (PoC) stream cipher based on **ChaCha**, supporting a **variable number of rounds** (from 2 to 1000+), with additional initial state mixing (**pre_mix_state**) to enhance the avalanche effect.  
This project is designed as a **PoC** to study the impact of non-standard round counts, internal state modification, and security based on avalanche and performance properties of the algorithm.

---

## Main Features

- **Variable number of rounds** (from 2 to 1000+).
- Support for **128-bit and 256-bit keys**.
- Support for **64-bit and 96-bit nonces**.
- Built-in **initial state pre-mixing** (similar to pre-mixing in hash constructions).
- **Keystream obfuscation** (simple masking).
- **Automatic tests on real data**:
  - **KAT (Known Answer Test)** — verifying deterministic encryption result.
  - **Avalanche test** — evaluating the avalanche effect (how many bits change when one key bit is flipped).
  - **Speed test (MB/s)** — measuring cipher throughput.
- **Multithreading via Rayon** — automatic parallel processing of multiple files.
- Secure destruction of secret data (via `zeroize` and `SecretBox`).

---

## Project Goals

1. **Study the effect of round counts** on performance and security.
2. **Evaluate avalanche effect** when varying parameters.
3. **Test the cipher on real-world data** (files of arbitrary size).

---

## Project Structure

- **ChaChaVR** — main cipher structure with:
  - `process()` — encryption and decryption.
  - `obfuscate_keystream()` — keystream obfuscation.
- **pre_mix_state()** — initial state mixing for better diffusion.
- **Test module**:
  - `test_file()` — complete test for a single file (KAT, Avalanche, Speed).
  - `real_world_tests()` — parallel file processing in a folder.

---

## How to Use

1. **Add dependencies:**
```bash
cargo add zeroize secrecy rand rayon
```

2. **Run tests on your directory:**
```rust
fn main() {
    let rounds = 42; // any even number >= 2
    let dir_path = "test_data"; // your folder with files
    real_world_tests(dir_path, rounds);
}
```

3. **Output will include:**
- Determinism check (KAT).
- Decryption verification.
- Avalanche effect estimation (bits changed on average per key bit flip).
- Encryption speed (MB/s).

---

## Example Output

```text
=== Real-World Tests ===
Found 5 files in test_data
File: "video.mp4" (4500000 bytes)
  KAT PASS
  Decryption PASS
  Avalanche: 256.12 bits per key bit flip
  Speed: 325.43 MB/s (elapsed: 0.013 s)
```

---

## Warning

> **ChaCha-VR is not a standard cipher and should not be used in production.**  
> This is an experimental research project to analyze how round counts and internal modifications affect security and performance.  
> **Not recommended for use in high-security environments without a full, independent audit.**

### AI Assistance

Some parts of this project (such as initial drafts, formatting, and testing ideas) were assisted by AI tools (like ChatGPT). However, all cryptographic logic, algorithmic design, and testing methodologies were developed(although, rather, written), reviewed, and finalized by the author as part of independent research.
---

## TODO (Ideas for Future)

- [ ] Add streaming (chunked) encryption for large files.
- [ ] Implement official test vectors (NIST, Wycheproof).
- [ ] Integration with Crypto API.
- [ ] More advanced keystream obfuscation (dynamic masks).
- [ ] Fully multithreaded mode splitting large files between threads (instead of one file per thread).

---

## Contacts

If you have questions or suggestions — **open an issue** or **fork the project**.

---

## License

MIT License. Free for non-commercial and research use.  
Use at your own risk.

---

## Why is this important?

This project helps answer questions like:

- **How does the avalanche effect change with low and high round counts?**
- **Does pre-mixing significantly improve security?**
- **What is the real encryption speed on large files?**
- **Can ChaCha be effectively customized for non-standard tasks?**

---