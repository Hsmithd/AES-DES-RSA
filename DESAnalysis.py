"""
DES (Data Encryption Standard) Implementation and Benchmark
Cody Kostlecky

DES is a symmetric encryption algorithm developed in the late 1970s.
- 64-bit plaintext input/output
- 64-bit key (56-bit effective, 8 parity bits)
- 16 rounds of encryption
- Block cipher with various modes
"""

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time
import matplotlib.pyplot as plt
import numpy as np


class DESAnalysis:
    def __init__(self):
        """Initialize DES key and test parameters"""
        # DES uses a 64-bit (8 byte) key
        # Every 8th bit is a parity bit, giving us 56 effective bits
        self.des_key = get_random_bytes(8)

        # Test with various data sizes (in bytes)
        self.test_sizes = [8, 64, 256, 1024, 4096, 16384, 65536]

        print("=" * 60)
        print("DES ENCRYPTION ALGORITHM ANALYSIS")
        print("=" * 60)
        print(f"DES Key (hex): {self.des_key.hex()}")
        print(f"Key Size: 64 bits (56 effective bits after parity)")
        print(f"Block Size: 64 bits (8 bytes)")
        print("=" * 60 + "\n")

    def des_encrypt(self, plaintext):
        """
        DES Encryption Process:
        1. Initial permutation of the plaintext
        2. 16 rounds of:
           - Split key in half
           - Circular rotation (1 or 2 bits depending on round)
           - Key compression (56 bits → 48 bits)
           - Expansion of plaintext half (32 bits → 48 bits)
           - XOR with compressed key
           - Substitution function (48 bits → 32 bits)
           - Permutation
        3. Final permutation

        Mode: CBC (Cipher Block Chaining) for security
        """
        # Create cipher object in CBC mode
        cipher = DES.new(self.des_key, DES.MODE_CBC)

        # Pad plaintext to be multiple of 8 bytes (DES block size)
        padded_text = pad(plaintext, DES.block_size)

        # Encrypt the padded plaintext
        ciphertext = cipher.encrypt(padded_text)

        # Return IV + ciphertext (IV needed for decryption)
        return cipher.iv + ciphertext

    def des_decrypt(self, ciphertext):
        """
        DES Decryption:
        Reverses the encryption process using the same key
        """
        # Extract the IV (first 8 bytes)
        iv = ciphertext[:8]

        # Extract the actual ciphertext
        actual_ciphertext = ciphertext[8:]

        # Create cipher object with the same IV
        cipher = DES.new(self.des_key, DES.MODE_CBC, iv)

        # Decrypt
        padded_plaintext = cipher.decrypt(actual_ciphertext)

        # Remove padding
        return unpad(padded_plaintext, DES.block_size)

    def verify_encryption(self):
        """Test that encryption and decryption work correctly"""
        test_message = b"Hello, this is a test message for DES encryption!"

        print("VERIFICATION TEST:")
        print(f"Original message: {test_message.decode()}")

        # Encrypt
        encrypted = self.des_encrypt(test_message)
        print(f"Encrypted (hex): {encrypted[:32].hex()}... ({len(encrypted)} bytes)")

        # Decrypt
        decrypted = self.des_decrypt(encrypted)
        print(f"Decrypted message: {decrypted.decode()}")

        # Verify
        if test_message == decrypted:
            print("✓ Encryption/Decryption successful!\n")
        else:
            print("✗ Error: Decryption failed!\n")

    def benchmark_des(self, plaintext, iterations=100):
        """
        Benchmark DES encryption and decryption performance

        Returns:
            - Average encryption time (seconds)
            - Average decryption time (seconds)
            - Throughput (MB/s)
        """
        # Benchmark encryption
        encrypt_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            ciphertext = self.des_encrypt(plaintext)
            end = time.perf_counter()
            encrypt_times.append(end - start)

        avg_encrypt_time = np.mean(encrypt_times)
        std_encrypt_time = np.std(encrypt_times)

        # Benchmark decryption
        ciphertext = self.des_encrypt(plaintext)
        decrypt_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            self.des_decrypt(ciphertext)
            end = time.perf_counter()
            decrypt_times.append(end - start)

        avg_decrypt_time = np.mean(decrypt_times)
        std_decrypt_time = np.std(decrypt_times)

        # Calculate throughput in MB/s
        data_size_mb = len(plaintext) / (1024 * 1024)
        encrypt_throughput = data_size_mb / avg_encrypt_time if avg_encrypt_time > 0 else 0
        decrypt_throughput = data_size_mb / avg_decrypt_time if avg_decrypt_time > 0 else 0

        return {
            'encrypt_time': avg_encrypt_time,
            'decrypt_time': avg_decrypt_time,
            'encrypt_std': std_encrypt_time,
            'decrypt_std': std_decrypt_time,
            'encrypt_throughput': encrypt_throughput,
            'decrypt_throughput': decrypt_throughput
        }

    def run_benchmarks(self):
        """Run comprehensive benchmarks across different data sizes"""
        results = {
            'sizes': [],
            'encrypt_times': [],
            'decrypt_times': [],
            'encrypt_throughput': [],
            'decrypt_throughput': [],
            'encrypt_std': [],
            'decrypt_std': []
        }

        print("RUNNING BENCHMARKS:")
        print("-" * 60)

        for size in self.test_sizes:
            # Generate random test data
            plaintext = get_random_bytes(size)

            print(f"\nData Size: {size:,} bytes ({size / 1024:.2f} KB)")

            # Run benchmark
            bench_result = self.benchmark_des(plaintext)

            # Store results
            results['sizes'].append(size)
            results['encrypt_times'].append(bench_result['encrypt_time'] * 1000)  # Convert to ms
            results['decrypt_times'].append(bench_result['decrypt_time'] * 1000)
            results['encrypt_throughput'].append(bench_result['encrypt_throughput'])
            results['decrypt_throughput'].append(bench_result['decrypt_throughput'])
            results['encrypt_std'].append(bench_result['encrypt_std'] * 1000)
            results['decrypt_std'].append(bench_result['decrypt_std'] * 1000)

            # Print results
            print(f"  Encryption: {bench_result['encrypt_time'] * 1000:.4f} ms "
                  f"(±{bench_result['encrypt_std'] * 1000:.4f} ms)")
            print(f"  Decryption: {bench_result['decrypt_time'] * 1000:.4f} ms "
                  f"(±{bench_result['decrypt_std'] * 1000:.4f} ms)")
            print(f"  Throughput: {bench_result['encrypt_throughput']:.2f} MB/s (encrypt), "
                  f"{bench_result['decrypt_throughput']:.2f} MB/s (decrypt)")

        print("\n" + "=" * 60)
        return results

    def visualize_results(self, results):
        """Create visualizations of benchmark results"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('DES Encryption Algorithm Performance Analysis',
                     fontsize=16, fontweight='bold')

        sizes_kb = [s / 1024 for s in results['sizes']]

        # Plot 1: Encryption vs Decryption Time
        ax1 = axes[0, 0]
        ax1.plot(sizes_kb, results['encrypt_times'], 'o-',
                 label='Encryption', linewidth=2, markersize=8, color='#2E86AB')
        ax1.plot(sizes_kb, results['decrypt_times'], 's-',
                 label='Decryption', linewidth=2, markersize=8, color='#A23B72')
        ax1.set_xlabel('Data Size (KB)', fontsize=11)
        ax1.set_ylabel('Time (milliseconds)', fontsize=11)
        ax1.set_title('DES Encryption/Decryption Time vs Data Size', fontsize=12)
        ax1.legend(fontsize=10)
        ax1.grid(True, alpha=0.3)
        ax1.set_xscale('log')
        ax1.set_yscale('log')

        # Plot 2: Throughput
        ax2 = axes[0, 1]
        ax2.plot(sizes_kb, results['encrypt_throughput'], 'o-',
                 label='Encryption', linewidth=2, markersize=8, color='#2E86AB')
        ax2.plot(sizes_kb, results['decrypt_throughput'], 's-',
                 label='Decryption', linewidth=2, markersize=8, color='#A23B72')
        ax2.set_xlabel('Data Size (KB)', fontsize=11)
        ax2.set_ylabel('Throughput (MB/s)', fontsize=11)
        ax2.set_title('DES Throughput Performance', fontsize=12)
        ax2.legend(fontsize=10)
        ax2.grid(True, alpha=0.3)
        ax2.set_xscale('log')

        # Plot 3: Time scaling (linear view)
        ax3 = axes[1, 0]
        ax3.plot(sizes_kb, results['encrypt_times'], 'o-',
                 linewidth=2, markersize=8, color='#2E86AB')
        ax3.fill_between(sizes_kb,
                         np.array(results['encrypt_times']) - np.array(results['encrypt_std']),
                         np.array(results['encrypt_times']) + np.array(results['encrypt_std']),
                         alpha=0.3, color='#2E86AB')
        ax3.set_xlabel('Data Size (KB)', fontsize=11)
        ax3.set_ylabel('Encryption Time (milliseconds)', fontsize=11)
        ax3.set_title('DES Encryption Time with Standard Deviation', fontsize=12)
        ax3.grid(True, alpha=0.3)

        # Plot 4: Performance summary bar chart
        ax4 = axes[1, 1]
        categories = ['Smallest\n(8 bytes)', 'Medium\n(4 KB)', 'Largest\n(64 KB)']
        encrypt_vals = [results['encrypt_times'][0],
                        results['encrypt_times'][4],
                        results['encrypt_times'][-1]]
        decrypt_vals = [results['decrypt_times'][0],
                        results['decrypt_times'][4],
                        results['decrypt_times'][-1]]

        x = np.arange(len(categories))
        width = 0.35

        bars1 = ax4.bar(x - width / 2, encrypt_vals, width, label='Encryption', color='#2E86AB')
        bars2 = ax4.bar(x + width / 2, decrypt_vals, width, label='Decryption', color='#A23B72')

        ax4.set_ylabel('Time (milliseconds)', fontsize=11)
        ax4.set_title('DES Performance Comparison by Data Size', fontsize=12)
        ax4.set_xticks(x)
        ax4.set_xticklabels(categories)
        ax4.legend(fontsize=10)
        ax4.grid(True, alpha=0.3, axis='y')

        # Add value labels on bars
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width() / 2., height,
                         f'{height:.3f}',
                         ha='center', va='bottom', fontsize=9)

        plt.tight_layout()
        plt.savefig('des_benchmark_results.png', dpi=300, bbox_inches='tight')
        print("\n✓ Visualization saved as 'des_benchmark_results.png'")
        plt.show()

    def print_des_info(self):
        """Print detailed information about DES"""
        print("\n" + "=" * 60)
        print("DES ALGORITHM INFORMATION")
        print("=" * 60)

        print("\nKEY CHARACTERISTICS:")
        print("  • Block Size: 64 bits (8 bytes)")
        print("  • Key Size: 64 bits (56 effective after parity bits)")
        print("  • Number of Rounds: 16")
        print("  • Type: Symmetric block cipher")
        print("  • Developed: Early 1970s, published 1977")

        print("\nENCRYPTION PROCESS:")
        print("  1. Initial Permutation (IP)")
        print("  2. 16 Rounds of:")
        print("     • Split plaintext block in half (L, R)")
        print("     • Key scheduling:")
        print("       - Split key in half")
        print("       - Circular rotation (1-2 bits per round)")
        print("       - Compression (56 → 48 bits)")
        print("     • Expansion function (32 → 48 bits)")
        print("     • XOR with round key")
        print("     • S-box substitution (48 → 32 bits)")
        print("     • Permutation")
        print("     • Swap halves")
        print("  3. Final Permutation (FP)")

        print("\nSTRENGTHS:")
        print("  • Well-studied and understood")
        print("  • Simple and efficient in hardware")
        print("  • Fast encryption/decryption")
        print("  • Good diffusion and confusion properties")

        print("\nWEAKNESSES:")
        print("  • 56-bit key is too small (vulnerable to brute force)")
        print("  • Broken in 1998 (56 hours with specialized hardware)")
        print("  • Considered cryptographically insecure today")
        print("  • Replaced by AES in 2001")

        print("\nLEGACY:")
        print("  • Triple DES (3DES) extends security by applying DES 3 times")
        print("  • Influential to modern cryptography development")
        print("  • Still used in some legacy systems")

        print("=" * 60)


def main():
    """Main execution function"""
    # Create DES analysis object
    des = DESAnalysis()

    # Verify that encryption/decryption works
    des.verify_encryption()

    # Run benchmarks
    results = des.run_benchmarks()

    # Visualize results
    des.visualize_results(results)

    # Print DES information
    # des.print_des_info()

    print("\n✓ DES Analysis Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()