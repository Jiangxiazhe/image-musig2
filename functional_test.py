import os
import shutil
import subprocess

import musig2

children = ['one', 'two', 'three']

sig = ''
X = b''


# 创建文件夹用于区分和储存不同用户的信息
def create_dirs():
    if os.path.exists("musig2-test"):
        shutil.rmtree("musig2-test")
    os.mkdir("musig2-test")
    for child in children:
        os.mkdir(f"musig2-test/{child}")
        musig2.write_bytes("hello world\n".encode(), f"musig2-test/{child}/message")


# 生成公钥密钥
def gen_pub_keys():
    keys = b''
    for child in children:
        one = subprocess.Popen(["python3", "../../musig2.py", "keygen"],
                        cwd=f"musig2-test/{child}",
                        stdout=subprocess.PIPE
                    )
        stdout, _ = one.communicate()
        pubkey = stdout.strip().split(b'\n')[-1]
        keys += pubkey + b'\n'
    for child in children:
        musig2.write_bytes(keys, f"musig2-test/{child}/public_keys")

def gen_nonces():
    nonces = b''
    for child in children:
        one = subprocess.Popen(["python3", "../../musig2.py", "noncegen"],
                        cwd=f"musig2-test/{child}",
                        stdout=subprocess.PIPE
                    )
        stdout, _ = one.communicate()
        stdout = stdout.strip().split(b'\n')
        nonces += stdout[-1] + b'\n'
    for child in children:
        musig2.write_bytes(nonces, f"musig2-test/{child}/public_nonces")

def do_sign():
    s_values = b''
    for child in children:
        one = subprocess.Popen(["python3", "../../musig2.py", "sign"],
                        cwd=f"musig2-test/{child}",
                        stdout=subprocess.PIPE
                    )
        stdout, _ = one.communicate()
        stdout = stdout.strip().split(b'\n')
        s_value = stdout[-1]
        global X
        X = stdout[-1].decode()
        s_values += s_value + b'\n'
    for child in children:
        musig2.write_bytes(s_values, f"musig2-test/{child}/s_values")

def aggregate_signatures():
    one = subprocess.Popen(["python3", "../../musig2.py", "aggregatesignature"],
                    cwd=f"musig2-test/one",
                    stdout=subprocess.PIPE
                )
    stdout, _ = one.communicate()
    global sig
    sig = stdout.strip().split(b'\n')[-1].split(b' ')[-1].decode()

def do_verify():
    print(f"X: {X}")
    #print(f"R: {R}")
    print(f"S: {sig}")
    one = subprocess.Popen(["python3", "../../musig2.py", "verify", X, sig],
                    cwd=f"musig2-test/one",
                    stdout=subprocess.PIPE
                )
    stdout, _ = one.communicate()
    print(stdout.decode())

def remove_single_use_files():
    for child in children:
        if os.path.exists(f"musig2-test/{child}/s_values"):
            os.remove(f"musig2-test/{child}/s_values")
        if os.path.exists(f"musig2-test/{child}/public_nonces"):
            os.remove(f"musig2-test/{child}/public_nonces")

def cleanup():
    if os.path.exists("musig2-test"):
        shutil.rmtree("musig2-test")

def main():

    create_dirs()
    gen_pub_keys()


    gen_nonces()
    do_sign()
    aggregate_signatures()
    do_verify()

    remove_single_use_files()

    # Sign a second message with the same public keys
    gen_nonces()
    do_sign()
    aggregate_signatures()
    do_verify()

    # cleanup()


if __name__ == "__main__":
    main()
