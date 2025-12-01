"""
RSA (Rivest–Shamir–Adleman) Implementation and Benchmark
Kirsten B.

RSA is an asymmetric (public-key) encryption algorithm introduced in 1977.
- Public / private key pair
- Typical key sizes: 1024, 2048, 3072, 4096 bits
- Based on the hardness of factoring large integers
- Used mainly for key exchange, digital signatures, and small messages
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import time
import matplotlib.pyplot as plt
import numpy as np


class RSAAnalysis:
    def __init__(self):
        """Initialize RSA key pair and test parameters"""
        # Generate a 2048-bit RSA key pair (common modern size)
        self.key = RSA.generate(2048)
        self.public_key = self.key.public_key()
        self.private_key = self.key

        # With 2048-bit RSA + OAEP, max message size is limited
        # For 2048-bit key + SHA-1 OAEP, max is 214 bytes; we'll stay under that.
        self.test_sizes = [16, 32, 64, 128, 190]

        print("=" * 60)
        print("RSA ENCRYPTION ALGORITHM ANALYSIS")
        print("=" * 60)
        print(f"Modulus (n) size: {self.key.size_in_bits()} bits")
        print(f"Public exponent (e): {self.key.e}")
        print("Key Type: Asymmetric (public/private key pair)")
        print("Cipher: RSA with PKCS#1 OAEP padding")
        print("=" * 60 + "\n")

    def rsa_encrypt(self, plaintext: bytes) -> bytes:
        """
        RSA Encryption Process (conceptually):
        1. Key generation: choose large primes p, q → n = p*q
        2. Public key (n, e) is used to encrypt:
           c = m^e mod n, with padding (OAEP)
        3. Private key (n, d) is used to decrypt:
           m = c^d mod n, remove padding

        NOTE: RSA is used for small messages (e.g., symmetric keys),
        not bulk file encryption.
        """
        cipher = PKCS1_OAEP.new(self.public_key)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext

    def rsa_decrypt(self, ciphertext: bytes) -> bytes:
        """RSA Decryption using the private key"""
        cipher = PKCS1_OAEP.new(self.private_key)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext

    def verify_encryption(self):
        """Test that encryption and decryption work correctly"""
        test_message = b"Hello, this is a test message for RSA encryption!"

        print("VERIFICATION TEST:")
        print(f"Original message: {test_message.decode()}")

        # Encrypt
        encrypted = self.rsa_encrypt(test_message)
        print(f"Encrypted (hex): {encrypted[:32].hex()}... ({len(encrypted)} bytes)")

        # Decrypt
        decrypted = self.rsa_decrypt(encrypted)
        print(f"Decrypted message: {decrypted.decode()}")

        # Verify
        if test_message == decrypted:
            print("✓ Encryption/Decryption successful!\n")
        else:
            print("✗ Error: Decryption failed!\n")

    def benchmark_rsa(self, plaintext: bytes, iterations: int = 100):
        """
        Benchmark RSA encryption and decryption performance

        Returns:
            - Average encryption time (seconds)
            - Average decryption time (seconds)
            - Throughput (MB/s) based on message size
        """
        # Benchmark encryption
        encrypt_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            ciphertext = self.rsa_encrypt(plaintext)
            end = time.perf_counter()
            encrypt_times.append(end - start)

        avg_encrypt_time = np.mean(encrypt_times)
        std_encrypt_time = np.std(encrypt_times)

        # Benchmark decryption (use a fixed ciphertext)
        ciphertext = self.rsa_encrypt(plaintext)
        decrypt_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            self.rsa_decrypt(ciphertext)
            end = time.perf_counter()
            decrypt_times.append(end - start)

        avg_decrypt_time = np.mean(decrypt_times)
        std_decrypt_time = np.std(decrypt_times)

        # Calculate throughput in MB/s (for the small message size)
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
        """Run comprehensive benchmarks across different message sizes"""
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
            # Generate random test message of given size
            plaintext = get_random_bytes(size)

            print(f"\nMessage Size: {size:,} bytes")

            # Run benchmark
            bench_result = self.benchmark_rsa(plaintext)

            # Store results
            results['sizes'].append(size)
            results['encrypt_times'].append(bench_result['encrypt_time'] * 1000)  # ms
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
            print(f"  Throughput: {bench_result['encrypt_throughput']:.6f} MB/s (encrypt), "
                  f"{bench_result['decrypt_throughput']:.6f} MB/s (decrypt)")

        print("\n" + "=" * 60)
        return results

    def visualize_results(self, results):
        """Create visualizations of benchmark results"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('RSA Encryption Algorithm Performance Analysis',
                     fontsize=16, fontweight='bold')

        sizes_bytes = results['sizes']

        # Plot 1: Encryption vs Decryption Time (log scale)
        ax1 = axes[0, 0]
        ax1.plot(sizes_bytes, results['encrypt_times'], 'o-',
                 label='Encryption', linewidth=2, markersize=8)
        ax1.plot(sizes_bytes, results['decrypt_times'], 's-',
                 label='Decryption', linewidth=2, markersize=8)
        ax1.set_xlabel('Message Size (bytes)', fontsize=11)
        ax1.set_ylabel('Time (milliseconds)', fontsize=11)
        ax1.set_title('RSA Encryption/Decryption Time vs Message Size', fontsize=12)
        ax1.legend(fontsize=10)
        ax1.grid(True, alpha=0.3)
        ax1.set_xscale('log')
        ax1.set_yscale('log')

        # Plot 2: Throughput
        ax2 = axes[0, 1]
        ax2.plot(sizes_bytes, results['encrypt_throughput'], 'o-',
                 label='Encryption', linewidth=2, markersize=8)
        ax2.plot(sizes_bytes, results['decrypt_throughput'], 's-',
                 label='Decryption', linewidth=2, markersize=8)
        ax2.set_xlabel('Message Size (bytes)', fontsize=11)
        ax2.set_ylabel('Throughput (MB/s)', fontsize=11)
        ax2.set_title('RSA Throughput Performance (per operation)', fontsize=12)
        ax2.legend(fontsize=10)
        ax2.grid(True, alpha=0.3)
        ax2.set_xscale('log')

        # Plot 3: Encryption time with std dev (linear)
        ax3 = axes[1, 0]
        ax3.plot(sizes_bytes, results['encrypt_times'], 'o-',
                 linewidth=2, markersize=8)
        ax3.fill_between(sizes_bytes,
                         np.array(results['encrypt_times']) - np.array(results['encrypt_std']),
                         np.array(results['encrypt_times']) + np.array(results['encrypt_std']),
                         alpha=0.3)
        ax3.set_xlabel('Message Size (bytes)', fontsize=11)
        ax3.set_ylabel('Encryption Time (milliseconds)', fontsize=11)
        ax3.set_title('RSA Encryption Time with Standard Deviation', fontsize=12)
        ax3.grid(True, alpha=0.3)

        # Plot 4: Performance summary bar chart
        ax4 = axes[1, 1]
        categories = [f'{sizes_bytes[0]} bytes',
                      f'{sizes_bytes[len(sizes_bytes)//2]} bytes',
                      f'{sizes_bytes[-1]} bytes']
        encrypt_vals = [results['encrypt_times'][0],
                        results['encrypt_times'][len(sizes_bytes)//2],
                        results['encrypt_times'][-1]]
        decrypt_vals = [results['decrypt_times'][0],
                        results['decrypt_times'][len(sizes_bytes)//2],
                        results['decrypt_times'][-1]]

        x = np.arange(len(categories))
        width = 0.35

        bars1 = ax4.bar(x - width / 2, encrypt_vals, width, label='Encryption')
        bars2 = ax4.bar(x + width / 2, decrypt_vals, width, label='Decryption')

        ax4.set_ylabel('Time (milliseconds)', fontsize=11)
        ax4.set_title('RSA Performance Comparison by Message Size', fontsize=12)
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
        plt.savefig('rsa_benchmark_results.png', dpi=300, bbox_inches='tight')
        print("\n✓ Visualization saved as 'rsa_benchmark_results.png'")
        plt.show()

    def print_rsa_info(self):
        """Print detailed information about RSA"""
        print("\n" + "=" * 60)
        print("RSA ALGORITHM INFORMATION")
        print("=" * 60)

        print("\nKEY CHARACTERISTICS:")
        print(f"  • Modulus size: {self.key.size_in_bits()} bits")
        print("  • Asymmetric: public key (encrypt/verify), private key (decrypt/sign)")
        print("  • Based on integer factorization problem")
        print("  • Introduced: 1977 (Rivest, Shamir, Adleman)")

        print("\nTYPICAL USES:")
        print("  • Secure key exchange (encrypt a symmetric session key)")
        print("  • Digital signatures and authentication")
        print("  • Small control messages, not bulk data encryption")

        print("\nSTRENGTHS:")
        print("  • Public-key system: no pre-shared secret needed")
        print("  • Widely analyzed and well-understood")
        print("  • Supports encryption and signatures")

        print("\nLIMITATIONS:")
        print("  • Much slower than symmetric ciphers (DES, AES)")
        print("  • Message size limited by key size and padding")
        print("  • Requires correct padding and key management")
        print("=" * 60)


def main():
    """Main execution function"""
    rsa = RSAAnalysis()

    # Verify that encryption/decryption works
    rsa.verify_encryption()

    # Run benchmarks
    results = rsa.run_benchmarks()

    # Visualize results
    rsa.visualize_results(results)

    # Optional: print more RSA info
    # rsa.print_rsa_info()

    print("\n✓ RSA Analysis Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
