import os
import cv2
import csv
import time
import psutil
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from main import encrypt_and_hide, extract_and_decrypt, generate_keys


# Function to calculate Mean Squared Error (MSE)
def calculate_mse(image1, image2):
    """Calculate MSE between two images."""
    # Make sure both images are same shape
    if image1.shape != image2.shape:
        raise ValueError("Images must be the same size")

    squared_error = np.sum((image1.astype("float") - image2.astype("float")) ** 2)

    # Standard MSE calculation
    mse = squared_error / (image1.shape[0] * image1.shape[1])

    if len(image1.shape) > 2:  # If the image has multiple channels
        mse /= image1.shape[2]

    return mse


# Function to calculate Peak Signal-to-Noise Ratio (PSNR)
def calculate_psnr(mse, max_pixel=255.0):
    """Compute Peak Signal-to-Noise Ratio given MSE."""
    if mse == 0:
        return float("inf")
    return 10 * np.log10(max_pixel**2 / mse)


# Function to calculate Structural Similarity Index (SSIM)
def calculate_ssim(image1, image2):
    """Calculate SSIM between two images."""
    # Convert images to grayscale if they're not already
    if len(image1.shape) > 2:
        gray1 = cv2.cvtColor(image1, cv2.COLOR_BGR2GRAY)
        gray2 = cv2.cvtColor(image2, cv2.COLOR_BGR2GRAY)
    else:
        gray1 = image1
        gray2 = image2

    # Manual implementation of SSIM
    C1 = (0.01 * 255) ** 2
    C2 = (0.03 * 255) ** 2

    # Compute means
    mu1 = cv2.GaussianBlur(gray1, (11, 11), 1.5)
    mu2 = cv2.GaussianBlur(gray2, (11, 11), 1.5)

    # Compute mean square
    mu1_sq = mu1 * mu1
    mu2_sq = mu2 * mu2
    mu1_mu2 = mu1 * mu2

    # Compute variances and covariance
    sigma1_sq = cv2.GaussianBlur(gray1 * gray1, (11, 11), 1.5) - mu1_sq
    sigma2_sq = cv2.GaussianBlur(gray2 * gray2, (11, 11), 1.5) - mu2_sq
    sigma12 = cv2.GaussianBlur(gray1 * gray2, (11, 11), 1.5) - mu1_mu2

    # SSIM formula
    num = (2 * mu1_mu2 + C1) * (2 * sigma12 + C2)
    den = (mu1_sq + mu2_sq + C1) * (sigma1_sq + sigma2_sq + C2)

    ssim_map = num / den
    ssim_index = np.mean(ssim_map)

    return ssim_index


# Function to extract text of specific length from a file
def extract_text_with_length(file_path, byte_length):
    """Extract text of specified byte length from a file."""
    with open(file_path, "rb") as f:
        content = f.read()

    # Ensure we don't exceed the file size
    if byte_length > len(content):
        print(
            f"Warning: Requested {byte_length} bytes but file only has {len(content)} bytes"
        )
        return content

    return content[:byte_length]


# Function to save text to a temporary file
def save_temp_text(content, output_path):
    """Save content to a temporary file."""
    with open(output_path, "wb") as f:
        f.write(content)


# Main evaluation function
def run_comprehensive_evaluation(crypto_mode="both"):
    """Run comprehensive evaluation with both classic and lightweight crypto."""
    # Paths setup
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cover_image_path = os.path.join(base_dir, "in/medical_image.png")
    temp_message_dir = os.path.join(base_dir, "eval_text")
    output_dir = os.path.join(base_dir, "eval_out")
    results_dir = os.path.join(base_dir, "results")

    os.makedirs(temp_message_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)
    # Paths setup
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cover_image_path = os.path.join(base_dir, "in/medical_image.png")
    temp_message_dir = os.path.join(base_dir, "eval_text")
    output_dir = os.path.join(base_dir, "eval_out")
    results_dir = os.path.join(base_dir, "results")

    os.makedirs(temp_message_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)

    # Setup crypto modes configuration
    crypto_configs = {
        "classic": {
            "keys_dir": "../keys",
            "public_key": "../keys/public_key.pem",
            "private_key": "../keys/private_key.pem",
            "key_size": 2048,
        },
        "lightweight": {
            "keys_dir": "../keys_light",
            "public_key": "../keys_light/public_key.pem",
            "private_key": "../keys_light/private_key.pem",
            "key_size": 256,
        },
    }

    # Message sizes to test (in bytes)
    message_sizes = [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192]

    # Determine which modes to evaluate
    modes_to_test = []
    if crypto_mode in ["classic", "both"]:
        modes_to_test.append("classic")
    if crypto_mode in ["lightweight", "both"]:
        modes_to_test.append("lightweight")

    # Load or create benchmark dataset
    secret_message = "This is a test message for benchmarking." * 100
    benchmark_file = os.path.join(temp_message_dir, "benchmark.txt")
    with open(benchmark_file, "w") as f:
        f.write(secret_message)

    # Main evaluation loop
    for mode in modes_to_test:
        print(f"\nEvaluating {mode.upper()} cryptography mode...")
        config = crypto_configs[mode]

        # Generate keys if needed
        if not os.path.exists(config["public_key"]):
            print(f"Generating {mode} keys...")
            os.makedirs(config["keys_dir"], exist_ok=True)
            generate_keys(config["keys_dir"], config["key_size"], mode)

        results_file = os.path.join(results_dir, f"metrics_{mode}.csv")
        with open(results_file, "w", newline="") as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=[
                    "Message_Size",
                    "Encryption_Time",
                    "Decryption_Time",
                    "Total_Time",
                    "Peak_Memory",
                    "CPU_Usage",
                    "MSE",
                    "PSNR",
                    "SSIM",
                    "Key_Size",
                    "Power_Usage_Est",
                ],
            )
            writer.writeheader()

            # Test each message size
            for size in message_sizes:
                print(f"\nTesting with message size: {size} bytes")

                # Prepare test message
                test_message = secret_message[:size]
                test_file = os.path.join(temp_message_dir, f"test_{size}.txt")
                with open(test_file, "w") as f:
                    f.write(test_message)

                try:
                    # Measure encryption performance
                    start_process = psutil.Process()
                    start_cpu_percent = start_process.cpu_percent()
                    start_memory = start_process.memory_info().rss / 1024 / 1024

                    t_start = time.time()
                    stego_file = os.path.join(output_dir, f"stego_{mode}_{size}.png")
                    encrypt_and_hide(
                        test_file,
                        cover_image_path,
                        stego_file,
                        config["public_key"],
                        alpha=0.1,
                        crypto_mode=mode,
                    )
                    encryption_time = time.time() - t_start

                    # Memory and CPU measurements
                    end_memory = start_process.memory_info().rss / 1024 / 1024
                    peak_memory = max(
                        0, end_memory - start_memory
                    )  # Ensure non-negative
                    cpu_usage = start_process.cpu_percent()

                    # Calculate image quality metrics
                    original = cv2.imread(cover_image_path)
                    stego = cv2.imread(stego_file)

                    mse = calculate_mse(original, stego)
                    psnr = calculate_psnr(mse)
                    ssim = calculate_ssim(original, stego)

                    # Estimate power usage (very rough estimation)
                    power_usage = cpu_usage * encryption_time * 0.1  # mWh

                    # Record metrics
                    writer.writerow(
                        {
                            "Message_Size": size,
                            "Encryption_Time": f"{encryption_time:.4f}",
                            "Decryption_Time": "N/A",
                            "Total_Time": f"{encryption_time:.4f}",
                            "Peak_Memory": f"{peak_memory:.2f}",
                            "CPU_Usage": f"{cpu_usage:.2f}",
                            "MSE": f"{mse:.10f}",
                            "PSNR": f"{psnr:.2f}",
                            "SSIM": f"{ssim:.4f}",
                            "Key_Size": config["key_size"],
                            "Power_Usage_Est": f"{power_usage:.4f}",
                        }
                    )

                    print(f"Results for {size} bytes ({mode}):")
                    print(f"Encryption Time: {encryption_time:.4f}s")
                    print(f"Peak Memory: {peak_memory:.2f}MB")
                    print(f"CPU Usage: {cpu_usage:.2f}%")
                    print(f"PSNR: {psnr:.2f}dB")
                    print(f"SSIM: {ssim:.4f}")
                    print(f"Est. Power Usage: {power_usage:.4f}mWh")

                except Exception as e:
                    print(f"Error processing size {size}: {e}")
                    continue

        print(f"\nResults saved to {results_file}")


def evaluate_crypto_performance():
    """Evaluate only the cryptographic operations performance"""
    print("\nEvaluating pure cryptographic performance...")

    test_sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
    test_data = {size: os.urandom(size) for size in test_sizes}

    results = {
        "classic": {"encrypt": [], "decrypt": []},
        "lightweight": {"encrypt": [], "decrypt": []},
    }

    # Initialize crypto instances
    classic = HybridCrypto()
    lightweight = LightweightCrypto()

    # Generate test keys if not exist
    if not os.path.exists("../keys/public_key.pem"):
        generate_keys("../keys", 2048, "classic")
    if not os.path.exists("../keys_light/public_key.pem"):
        generate_keys("../keys_light", 256, "lightweight")

    for size in test_sizes:
        data = test_data[size]
        print(f"\nTesting with {size/1024:.1f}KB data:")

        # Test classic RSA+AES
        start = time.time()
        encrypted, key = classic.encrypt(data, "../keys/public_key.pem")
        classic_enc_time = time.time() - start

        start = time.time()
        classic.decrypt(encrypted, key, "../keys/private_key.pem")
        classic_dec_time = time.time() - start

        # Test lightweight ECC+ChaCha20
        start = time.time()
        encrypted, key = lightweight.encrypt(data, "../keys_light/public_key.pem")
        light_enc_time = time.time() - start

        start = time.time()
        lightweight.decrypt(encrypted, key, "../keys_light/private_key.pem")
        light_dec_time = time.time() - start

        print(
            f"Classic (RSA+AES):     Encrypt: {classic_enc_time:.4f}s, Decrypt: {classic_dec_time:.4f}s"
        )
        print(
            f"Lightweight (ECC+ChaCha20): Encrypt: {light_enc_time:.4f}s, Decrypt: {light_dec_time:.4f}s"
        )
        print(
            f"Improvement: {((classic_enc_time + classic_dec_time) / (light_enc_time + light_dec_time)):.2f}x faster"
        )


if __name__ == "__main__":
    run_comprehensive_evaluation("both")
