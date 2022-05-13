import os
import shutil

import musig2 as m2

children = ['one', 'two']

sig = ''
X = b''


# 创建文件夹用于区分和储存不同用户的信息
def create_dirs():
    if os.path.exists("ms2test"):
        shutil.rmtree("ms2test")
    os.mkdir("ms2test")
    for child in children:
        os.mkdir(f"ms2test/{child}")
        m2.write_bytes("hello world\n".encode(), f"ms2test/{child}/message")


# 生成公钥密钥
def keysgen():
    keys = b''
    keyl = []
    for child in children:
        seckey = m2.seckey_gen()
        seckeyl = []
        seckeyl.append(seckey)
        if not m2.write_bytes(seckey, f"ms2test/{child}/{m2.SECRET_KEY_FILE}"):
            seckey = m2.read_bytes(f"ms2test/{child}/{m2.SECRET_KEY_FILE}")
        print(f"Your secret key:\n{seckey.hex()}")
        pubkey = m2.pubkey_gen(seckey)
        print(f"Your public key:\n{pubkey.hex()}")
        keys += pubkey + b'\n'
        keyl.append(pubkey)
    for child in children:
        m2.write_bytes_list_to_hex(keyl, f"ms2test/{child}/public_keys")


# 聚合密钥
def aggregatekeys():
    public_keys_list = m2.read_bytes_from_hex_list("public_keys")
    combined_key, _ = m2.aggregate_public_keys(public_keys_list, None)
    combined_key_bytes = m2.bytes_from_point(combined_key)
    print(f"Aggregate public key:\n{combined_key_bytes.hex()}")


# 生成nonce，一个nonce只能使用一次
def nonceasgen():
    nl = []
    for child in children:
        nonce_secrets = []
        nonces = b''
        for _ in range(m2.nu):
            # Generate a secret key
            r_1j = m2.seckey_gen(force_even_y=False)
            # R_1j will be in 33-byte compressed key form with a parity byte
            R_1j = m2.pubkey_gen(r_1j, compressed=True)
            # Add this newly generated keypair to the lists
            nonce_secrets.append(r_1j)
            nonces += R_1j

        # Print the public nonce
        print(f"Your new nonce:\n{nonces.hex()}")
        # Encode the nonce secrets as a newline-separated list
        m2.write_bytes_list_to_hex(nonce_secrets, f"ms2test/{child}/{m2.SECRET_NONCE_FILE}")
        nl.append(nonces)
    for child in children:
        m2.write_bytes_list_to_hex(nl, f"ms2test/{child}/public_nonces")


# 签名
def sign(child: str):
    message = m2.get_message(f"ms2test/{child}/message")
    seckey = m2.read_bytes(f"ms2test/{child}/secret.key")
    pubkey = m2.pubkey_gen(seckey)
    # 计算聚合公钥
    public_keys_list = m2.read_bytes_from_hex_list(f"ms2test/{child}/public_keys")
    combined_key, a_1 = m2.aggregate_public_keys(public_keys_list, pubkey)
    combined_key_bytes = m2.bytes_from_point(combined_key)
    print(f"Aggregate key:\n{combined_key_bytes.hex()}")

    # 聚合所有参与者的nonces并计算R
    public_nonce_list = m2.read_bytes_from_hex_list(f"ms2test/{child}/public_nonces")
    if len(public_nonce_list) != len(public_keys_list):
        print("Error: mismatch between number of nonces and number of public keys.")
        quit()
    aggregated_nonce_points = m2.aggregate_nonces(public_nonce_list)
    aggregated_nonce_bytes = [m2.bytes_from_point(R, compressed=True) for R in aggregated_nonce_points]
    b = m2.hash_nonces(combined_key_bytes, aggregated_nonce_bytes, message)
    R = m2.compute_R(aggregated_nonce_points, b)
    R_bytes = m2.bytes_from_point(R)
    print(f"Signature R:\n{R_bytes.hex()}")

    # Compute challenge
    c = m2.chall_hash(combined_key_bytes, R_bytes, message)

    # 签名
    nonce_secrets = m2.read_bytes_from_hex_list(f"ms2test/{child}/{m2.SECRET_NONCE_FILE}")
    if not m2.has_even_y(R):
        # Negate all the nonce secrets if the R value has an odd y coordinate
        nonce_secrets = [m2.bytes_from_int(m2.n - m2.int_from_bytes(r)) for r in nonce_secrets]
    if not m2.has_even_y(combined_key):
        seckey = m2.bytes_from_int(m2.n - m2.int_from_bytes(seckey))
    s_1 = m2.compute_s(c, seckey, a_1, nonce_secrets, b)
    s_1_bytes = m2.bytes_from_int(s_1)
    print(f"Partial signature s_1:\n{s_1_bytes.hex()}")

    with open(f"ms2test/{child}/message.partsig", "w") as f:
        f.write(f"{combined_key_bytes.hex()}\n{R_bytes.hex()}\n{s_1_bytes.hex()}\n")
    # Delete the nonce secrets to ensure they are not reused multiple times
    # os.remove(f"mtest/{child}/{m2.SECRET_NONCE_FILE}")
    global X
    X = s_1_bytes
    return s_1_bytes


# 聚合签名
def aggresignalture(child: str):
    signature_bytes = b''
    message = m2.get_message(f"ms2test/{child}/message")
    # Sum the partial signature values from all signers
    s = 0
    sig_bytes_list = m2.read_bytes_from_hex_list(f"ms2test/{child}/{m2.S_VALUES_FILE}")
    for s_i in sig_bytes_list:
        s += m2.int_from_bytes(s_i)
        s %= m2.n
    s_bytes = m2.bytes_from_int(s)

    # Retrieve the R value from the partsig file
    partsig_bytes_list = m2.read_bytes_from_hex_list(f"ms2test/{child}/message.partsig")
    R_bytes = partsig_bytes_list[1]
    # Combine to produce the final signature
    signature_bytes = R_bytes + s_bytes
    return signature_bytes.hex()


# 验签
def verify(child: str):
    public_keys_list = m2.read_bytes_from_hex_list(f"ms2test/{child}/public_keys")
    pubkey, _ = m2.aggregate_public_keys(public_keys_list, None)
    pubkey_bytes = m2.bytes_from_point(pubkey)
    print(f"pubkey_bytes: \n{pubkey_bytes.hex()}")
    if len(pubkey_bytes) != 32:
        print("Error: length of public key must be 32 bytes")
        quit()
    signature_bytes = bytes.fromhex(sig)
    if len(signature_bytes) != 64:
        print("Error: length of signature must be 64 bytes")
        quit()
    message = m2.get_message(f"ms2test/{child}/message")
    R = signature_bytes[0:32]
    s = m2.int_from_bytes(signature_bytes[32:64])

    valid = m2.verify_sig(pubkey_bytes, message, R, s)
    print(f"Signature is valid: {valid}")


def sign_test():
    keysgen()
    nonceasgen()
    # root = os.getcwd()
    # os.chdir("ms2test/one")
    # aggregatekeys()
    # os.chdir(root)
    s_vl = []
    for child in children:
        s_vl.append(sign(child))
    for child in children:
        m2.write_bytes_list_to_hex(s_vl, f"ms2test/{child}/s_values")
    global sig
    for child in children:
        sig = aggresignalture(child)
    print(f"Hex-encoded signature:\n{sig}")


def verify_test():
    child = "one"
    verify(child)


if __name__ == "__main__":
    create_dirs()
    sign_test()
    verify_test()
    # m2.remove_single_use_files(children)
