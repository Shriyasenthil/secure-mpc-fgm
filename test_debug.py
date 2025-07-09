# test_debug.py - Debug fixed-point LabHE logic

import numpy as np
import labhe
from gmpy2 import mpz
import argparse

def debug_encrypt_decrypt():
    """First, verify basic encryption/decryption works"""
    lf = 16
    privkey, pubkey = labhe.Init(2048)
    
    print("=== Testing Basic Encryption/Decryption ===")
    test_vals = [1.0, 2.0, -1.0, 0.5]
    
    for val in test_vals:
        ct = labhe.encrypt(val, f"test_{val}", lf)
        decrypted = labhe.decrypt(privkey, ct, lf)
        print(f"Original: {val}, Decrypted: {decrypted}, Diff: {abs(val - decrypted)}")
        
        if abs(val - decrypted) > 1e-3:
            print("❌ Basic encryption/decryption is broken!")
            return False
    
    print("✅ Basic encryption/decryption works")
    return True

def debug_scalar_multiplication():
    """Test scalar multiplication step by step"""
    lf = 16
    scale = 1 << lf
    privkey, pubkey = labhe.Init(2048)
    
    print("\n=== Testing Scalar Multiplication ===")
    
    # Test 1: Simple integer multiplication
    ct = labhe.encrypt(2.0, "test", lf)
    result_ct = labhe.Eval_mult_scalar(pubkey, ct, 3)  # 2.0 * 3 = 6.0
    result = labhe.decrypt(privkey, result_ct, lf)
    print(f"2.0 * 3 = {result} (expected: 6.0)")
    
    # Test 2: Multiplication by 1
    result_ct = labhe.Eval_mult_scalar(pubkey, ct, 1)
    result = labhe.decrypt(privkey, result_ct, lf)
    print(f"2.0 * 1 = {result} (expected: 2.0)")
    
    # Test 3: Problematic scaling
    print("\n--- Testing problematic scaling ---")
    problematic_scalar = int(round(1.0 * scale))
    print(f"Problematic scalar (scaled again): {problematic_scalar}")
    
    result_ct = labhe.Eval_mult_scalar(pubkey, ct, problematic_scalar)
    result = labhe.decrypt(privkey, result_ct, lf)
    print(f"2.0 * {problematic_scalar} = {result} (⚠ expected to be huge)")

    if abs(result) > 1e6:
        print("  ⚠️  WRONG METHOD exploded!")
    else:
        print("  ✅ WRONG METHOD unexpectedly stable")

    print("✅ Scalar multiplication test completed.")

def debug_matrix_vector_step_by_step():
    """Debug matrix-vector multiplication step by step"""
    lf = 16
    scale = 1 << lf
    privkey, pubkey = labhe.Init(2048)
    
    print("\n=== Testing Matrix-Vector Multiplication Step-by-Step ===")
    
    I = np.array([[1.0, 0.0], [0.0, 1.0]])
    vec = [1.0, 2.0]
    
    print(f"Matrix:\n{I}")
    print(f"Vector: {vec}")
    
    # Encrypt the vector
    enc_vec = []
    for i, x in enumerate(vec):
        ct = labhe.encrypt(x, f"vec_{i}", lf)
        decrypted = labhe.decrypt(privkey, ct, lf)
        print(f"Encrypted vec[{i}]: {x} -> {decrypted}")
        enc_vec.append(ct)
    
    # Matrix-vector multiplication
    print("\n--- Manual matrix-vector multiplication ---")
    result = []
    
    for i, row in enumerate(I):
        print(f"\nRow {i}: {row}")
        acc = None
        
        for j, scalar in enumerate(row):
            print(f"  Processing element [{i},{j}] = {scalar}")
            if scalar == 0:
                print("    Skipping zero element")
                continue
            
            wrong_scalar = int(round(scalar * scale))  # old broken way
            right_scalar = int(round(scalar))           # correct fixed-point way
            
            print(f"    Wrong scalar (old method): {wrong_scalar}")
            print(f"    Right scalar (new method): {right_scalar}")
            
            prod_wrong = labhe.Eval_mult_scalar(pubkey, enc_vec[j], mpz(wrong_scalar))
            prod_right = labhe.Eval_mult_scalar(pubkey, enc_vec[j], mpz(right_scalar))
            
            decrypted_wrong = labhe.decrypt(privkey, prod_wrong, lf)
            decrypted_right = labhe.decrypt(privkey, prod_right, lf)
            
            print(f"    ❌ Wrong result: {decrypted_wrong}")
            print(f"    ✅ Right result: {decrypted_right}")
            
            if abs(decrypted_wrong) > 1e6:
                print("    ⚠️  WRONG METHOD exploded!")
            if acc is None:
                acc = prod_right
            else:
                acc = labhe.Eval_add(pubkey, acc, prod_right)
        
        if acc is None:
            acc = labhe.Eval_mult_scalar(pubkey, enc_vec[0], mpz(0))
        
        result.append(acc)
    
    # Decrypt final result
    final_result = []
    for i, ct in enumerate(result):
        decrypted = labhe.decrypt(privkey, ct, lf)
        final_result.append(decrypted)
        print(f"Final result[{i}]: {decrypted}")
    
    print(f"\nInput vector: {vec}")
    print(f"Output vector: {final_result}")
    print(f"Expected (I * vec): {vec}")
    print("✅ Matrix-vector multiplication test completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', choices=['all', 'basic', 'scalar', 'matvec'], default='all')
    args = parser.parse_args()

    if args.test in ['all', 'basic']:
        if not debug_encrypt_decrypt():
            exit(1)

    if args.test in ['all', 'scalar']:
        debug_scalar_multiplication()

    if args.test in ['all', 'matvec']:
        debug_matrix_vector_step_by_step()
