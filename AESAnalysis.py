"""
AES (Advanced Encryption Standard) Implementation and Benchmark
Hayden Smith

AES is the modern symmetric encryption standard replacing DES.
- 128-bit block size
- 128/192/256-bit keys (using 256-bit here)
- 10/12/14 rounds depending on key size
- Secure, efficient, and widely deployed
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time
import matplotlib.pyplot as plt
import numpy as np


class AESAnalysis:
    def __init__(self):
        """Initialize AES key and test parameters"""
        # AES supports 128/192/256-bit keys; we use 256-bit (32 bytes) for maximum strength
        self.aes_key = get_random_bytes(32)

        # Test with various data sizes (in bytes)
        self.test_sizes = [16, 64, 256, 1024, 4096, 16384, 65536]

        print("=" * 60)
        print("AES ENCRYPTION ALGORITHM ANALYSIS")
        print("=" * 60)
        print(f"AES Key (hex): {self.aes_key.hex()}")
        print("Key Size: 256 bits (32 bytes)")
        print("Block Size: 128 bits (16 bytes)")
        print("=" * 60 + "\n")

    def aes_encrypt(self, plaintext):
        """
        AES Encryption Process (CBC mode):
        1. Key expansion to generate round keys
        2. Initial AddRoundKey
        3. Repeated rounds of:
           - SubBytes
           - ShiftRows
           - MixColumns (omitted in final round)
           - AddRoundKey
        4. Final round without MixColumns

        Mode: CBC (Cipher Block Chaining) for confidentiality
        """
        # Create cipher object in CBC mode
        cipher = AES.new(self.aes_key, AES.MODE_CBC)

        # Pad plaintext to be multiple of 16 bytes (AES block size)
        padded_text = pad(plaintext, AES.block_size)

        # Encrypt the padded plaintext
        ciphertext = cipher.encrypt(padded_text)

        # Return IV + ciphertext (IV needed for decryption)
        return cipher.iv + ciphertext

    def aes_decrypt(self, ciphertext):
        """AES decryption reverses the encryption steps using the same key"""
        # Extract the IV (first 16 bytes)
        iv = ciphertext[: AES.block_size]

        # Extract the actual ciphertext
        actual_ciphertext = ciphertext[AES.block_size :]

        # Create cipher object with the same IV
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)

        # Decrypt and remove padding
        padded_plaintext = cipher.decrypt(actual_ciphertext)
        return unpad(padded_plaintext, AES.block_size)

    def verify_encryption(self):
        """Test that AES encryption and decryption work correctly"""
        test_message = b"Hello, this is a test message for AES encryption!"

        print("VERIFICATION TEST:")
        print(f"Original message: {test_message.decode()}")

        # Encrypt
        encrypted = self.aes_encrypt(test_message)
        print(f"Encrypted (hex): {encrypted[:32].hex()}... ({len(encrypted)} bytes)")

        # Decrypt
        decrypted = self.aes_decrypt(encrypted)
        print(f"Decrypted message: {decrypted.decode()}")

        # Verify
        if test_message == decrypted:
            print("[OK] Encryption/Decryption successful!\n")
        else:
            print("[ERROR] Decryption failed!\n")

    def benchmark_aes(self, plaintext, iterations=100):
        """
        Benchmark AES encryption and decryption performance

        Returns:
            - Average encryption time (seconds)
            - Average decryption time (seconds)
            - Throughput (MB/s)
        """
        # Benchmark encryption
        encrypt_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            ciphertext = self.aes_encrypt(plaintext)
            end = time.perf_counter()
            encrypt_times.append(end - start)

        avg_encrypt_time = np.mean(encrypt_times)
        std_encrypt_time = np.std(encrypt_times)

        # Benchmark decryption
        ciphertext = self.aes_encrypt(plaintext)
        decrypt_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            self.aes_decrypt(ciphertext)
            end = time.perf_counter()
            decrypt_times.append(end - start)

        avg_decrypt_time = np.mean(decrypt_times)
        std_decrypt_time = np.std(decrypt_times)

        # Calculate throughput in MB/s
        data_size_mb = len(plaintext) / (1024 * 1024)
        encrypt_throughput = data_size_mb / avg_encrypt_time if avg_encrypt_time > 0 else 0
        decrypt_throughput = data_size_mb / avg_decrypt_time if avg_decrypt_time > 0 else 0

        return {
            "encrypt_time": avg_encrypt_time,
            "decrypt_time": avg_decrypt_time,
            "encrypt_std": std_encrypt_time,
            "decrypt_std": std_decrypt_time,
            "encrypt_throughput": encrypt_throughput,
            "decrypt_throughput": decrypt_throughput,
        }

    def run_benchmarks(self):
        """Run benchmarks across different data sizes"""
        results = {
            "sizes": [],
            "encrypt_times": [],
            "decrypt_times": [],
            "encrypt_throughput": [],
            "decrypt_throughput": [],
            "encrypt_std": [],
            "decrypt_std": [],
        }

        print("RUNNING BENCHMARKS:")
        print("-" * 60)

        for size in self.test_sizes:
            # Generate random test data
            plaintext = get_random_bytes(size)

            print(f"\nData Size: {size:,} bytes ({size / 1024:.2f} KB)")

            # Run benchmark
            bench_result = self.benchmark_aes(plaintext)

            # Store results
            results["sizes"].append(size)
            results["encrypt_times"].append(bench_result["encrypt_time"] * 1000)  # ms
            results["decrypt_times"].append(bench_result["decrypt_time"] * 1000)
            results["encrypt_throughput"].append(bench_result["encrypt_throughput"])
            results["decrypt_throughput"].append(bench_result["decrypt_throughput"])
            results["encrypt_std"].append(bench_result["encrypt_std"] * 1000)
            results["decrypt_std"].append(bench_result["decrypt_std"] * 1000)

            # Print results
            print(
                f"  Encryption: {bench_result['encrypt_time'] * 1000:.4f} ms "
                f"(±{bench_result['encrypt_std'] * 1000:.4f} ms)"
            )
            print(
                f"  Decryption: {bench_result['decrypt_time'] * 1000:.4f} ms "
                f"(±{bench_result['decrypt_std'] * 1000:.4f} ms)"
            )
            print(
                "  Throughput: "
                f"{bench_result['encrypt_throughput']:.2f} MB/s (encrypt), "
                f"{bench_result['decrypt_throughput']:.2f} MB/s (decrypt)"
            )

        print("\n" + "=" * 60)
        return results

    def visualize_results(self, results):
        """Create visualizations of benchmark results"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle("AES Encryption Algorithm Performance Analysis", fontsize=16, fontweight="bold")

        sizes_kb = [s / 1024 for s in results["sizes"]]

        # Plot 1: Encryption vs Decryption Time
        ax1 = axes[0, 0]
        ax1.plot(
            sizes_kb,
            results["encrypt_times"],
            "o-",
            label="Encryption",
            linewidth=2,
            markersize=8,
            color="#2E86AB",
        )
        ax1.plot(
            sizes_kb,
            results["decrypt_times"],
            "s-",
            label="Decryption",
            linewidth=2,
            markersize=8,
            color="#A23B72",
        )
        ax1.set_xlabel("Data Size (KB)", fontsize=11)
        ax1.set_ylabel("Time (milliseconds)", fontsize=11)
        ax1.set_title("AES Encryption/Decryption Time vs Data Size", fontsize=12)
        ax1.legend(fontsize=10)
        ax1.grid(True, alpha=0.3)
        ax1.set_xscale("log")
        ax1.set_yscale("log")

        # Plot 2: Throughput
        ax2 = axes[0, 1]
        ax2.plot(
            sizes_kb,
            results["encrypt_throughput"],
            "o-",
            label="Encryption",
            linewidth=2,
            markersize=8,
            color="#2E86AB",
        )
        ax2.plot(
            sizes_kb,
            results["decrypt_throughput"],
            "s-",
            label="Decryption",
            linewidth=2,
            markersize=8,
            color="#A23B72",
        )
        ax2.set_xlabel("Data Size (KB)", fontsize=11)
        ax2.set_ylabel("Throughput (MB/s)", fontsize=11)
        ax2.set_title("AES Throughput Performance", fontsize=12)
        ax2.legend(fontsize=10)
        ax2.grid(True, alpha=0.3)
        ax2.set_xscale("log")

        # Plot 3: Time scaling (linear view)
        ax3 = axes[1, 0]
        ax3.plot(
            sizes_kb,
            results["encrypt_times"],
            "o-",
            linewidth=2,
            markersize=8,
            color="#2E86AB",
        )
        ax3.fill_between(
            sizes_kb,
            np.array(results["encrypt_times"]) - np.array(results["encrypt_std"]),
            np.array(results["encrypt_times"]) + np.array(results["encrypt_std"]),
            alpha=0.3,
            color="#2E86AB",
        )
        ax3.set_xlabel("Data Size (KB)", fontsize=11)
        ax3.set_ylabel("Encryption Time (milliseconds)", fontsize=11)
        ax3.set_title("AES Encryption Time with Standard Deviation", fontsize=12)
        ax3.grid(True, alpha=0.3)

        # Plot 4: Performance summary bar chart
        ax4 = axes[1, 1]
        categories = ["Smallest\n(16 bytes)", "Medium\n(4 KB)", "Largest\n(64 KB)"]
        encrypt_vals = [
            results["encrypt_times"][0],
            results["encrypt_times"][4],
            results["encrypt_times"][-1],
        ]
        decrypt_vals = [
            results["decrypt_times"][0],
            results["decrypt_times"][4],
            results["decrypt_times"][-1],
        ]

        x = np.arange(len(categories))
        width = 0.35

        bars1 = ax4.bar(x - width / 2, encrypt_vals, width, label="Encryption", color="#2E86AB")
        bars2 = ax4.bar(x + width / 2, decrypt_vals, width, label="Decryption", color="#A23B72")

        ax4.set_ylabel("Time (milliseconds)", fontsize=11)
        ax4.set_title("AES Performance Comparison by Data Size", fontsize=12)
        ax4.set_xticks(x)
        ax4.set_xticklabels(categories)
        ax4.legend(fontsize=10)
        ax4.grid(True, alpha=0.3, axis="y")

        # Add value labels on bars
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                ax4.text(
                    bar.get_x() + bar.get_width() / 2.0,
                    height,
                    f"{height:.3f}",
                    ha="center",
                    va="bottom",
                    fontsize=9,
                )

        plt.tight_layout()
        plt.savefig("aes_benchmark_results.png", dpi=300, bbox_inches="tight")
        print("\n[OK] Visualization saved as 'aes_benchmark_results.png'")
        plt.show()

    def print_aes_info(self):
        """Print detailed information about AES"""
        print("\n" + "=" * 60)
        print("AES ALGORITHM INFORMATION")
        print("=" * 60)

        print("\nKEY CHARACTERISTICS:")
        print("  - Block Size: 128 bits (16 bytes)")
        print("  - Key Sizes: 128, 192, or 256 bits")
        print("  - Rounds: 10/12/14 for 128/192/256-bit keys")
        print("  - Type: Symmetric block cipher")
        print("  - Standardized: FIPS 197 (2001)")

        print("\nENCRYPTION PROCESS:")
        print("  1. Key expansion to generate round keys")
        print("  2. Initial AddRoundKey")
        print("  3. 9/11/13 rounds of:")
        print("     - SubBytes (non-linear substitution)")
        print("     - ShiftRows (row permutation)")
        print("     - MixColumns (column mixing)")
        print("     - AddRoundKey (XOR with round key)")
        print("  4. Final round without MixColumns")

        print("\nSTRENGTHS:")
        print("  - Strong security with 128+ bit keys")
        print("  - Efficient in both software and hardware")
        print("  - Supported by hardware acceleration (AES-NI, ARMv8)")
        print("  - Widely vetted and standardized")

        print("\nWEAKNESSES/CONSIDERATIONS:")
        print("  - Requires proper IV/nonce usage for security")
        print("  - Vulnerable to side-channel attacks without countermeasures")
        print("  - Small block size can lead to pattern leaks if misused in ECB")

        print("\nUSAGE AND LEGACY:")
        print("  - Used in TLS, IPSec, disk encryption, and many protocols")
        print("  - Replaced DES and Triple DES as the modern standard")
        print("  - Foundation for many authenticated modes (GCM, CCM)")

        print("=" * 60)


def main():
    """Main execution function"""
    aes = AESAnalysis()

    # Verify that encryption/decryption works
    aes.verify_encryption()

    # Run benchmarks
    results = aes.run_benchmarks()

    # Visualize results
    aes.visualize_results(results)

    # Print AES information
    # aes.print_aes_info()

    print("\n[OK] AES Analysis Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
