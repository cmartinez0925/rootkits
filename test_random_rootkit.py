# test_random_rootkit.py
import os

print("Testing /dev/urandom hook...")

# Read directly from the device file
with open('/dev/urandom', 'rb') as f:
    data = f.read(100)

# Check if all bytes are zero
all_zeros = all(byte == 0 for byte in data)

if all_zeros:
    print("✓ SUCCESS: All bytes are 0x00 (rootkit is working!)")
    print(f"Sample: {data[:20].hex()}")
else:
    print("✗ FAILED: Got random data (rootkit not working)")
    print(f"Sample: {data[:20].hex()}")
    
# Count zeros
zero_count = sum(1 for byte in data if byte == 0)
print(f"Zero bytes: {zero_count}/100")