# musig2-py
Experimental MuSig2 python code, not for production use! This is just for testing things out. As experimental code, please also expect it to change in breaking ways between commits.

MuSig2 is described in [this paper](https://eprint.iacr.org/2020/1261) by Jonas Nick, Tim Ruffing, and Yannick Seurin, which was published at CRYPTO'21. This implementation also (maybe?) follows the draft specification [here](https://github.com/ElementsProject/secp256k1-zkp/pull/157), but compatibility with [zecp256k1-zkp](https://github.com/ElementsProject/secp256k1-zkp)'s implementation is untested.

Public keys are encoded as 32 bytes, assuming an even y coordinate, as in [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

Nonces consist of two 33-bytes public keys concatenated, for 66 bytes in total. These 33-byte public keys are in compressed form, and consist of a parity byte (`0x02` if the y-coordinate is even and `0x03` otherwise), followed by the 32-byte x-coordinate.

Signatures are 64 bytes. The first 32 bytes encode the x-coordinate of the point R (which is again assumed to have an even y coordinate). The second 32 bytes encode the integer s. This makes them compatible with [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki), and hence valid as [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) Taproot Schnorr signatures.

## Usage

1. First generate a public and private keypair:

```
> python3 musig2.py keygen
Your public key:
1a9abf430360780ce7c9fdcb63381d0fe1dcb8618b93ee5076fe8cd9bc3eece1
```

This will create a file `secret.key` containing the secret key for the above public key. Keep this safe.

2. Send your public key to all other participants involved with this MuSig2 aggregate signing key.

3. Receive from all participants their public keys and create a file called `public_keys` containing all these keys (including your own). The order is not important. For example:

```
1a9abf430360780ce7c9fdcb63381d0fe1dcb8618b93ee5076fe8cd9bc3eece1
4c778668e7cb6467a04c190eb9dad466006f84e18f35598f6ac5a4662009102d
8470d74a5ff04928eaec2e1dc5562c1a7ea7a7cce913901bdec031bda84eeecf
```

4. Generate the aggregate public key:

```
> python3 musig2.py aggregatekeys
Aggregate public key:
6a3ebe79463836eeff69fffe493d3c42d8c5bbd47fcfaf40aa6a6026c45ab535
```

This public key will be the final public key used for verification of the signature. It can be used as many times as you (and your co-signers) like. You will need to generate new nonces every time you wish to sign with it, however.

5. Generate a single-use nonce:

```
> python3 musig2.py noncegen
WARNING: Only use this nonce once, then generate a new one.
Reusing nonces to sign different messages will leak your secret key.
Your new nonce:
02cf08c1684b35870f2a9231d75a1e8b9ac343f31e0622f7dac55beb195607cd170238cbaebcac547896d97bb7d2ca6af9b404e01c85652e5c1356161e13d651431b
```

This will also create a file `secret_nonces` containing the secrets corresponding to this nonce.

6. Send your nonce to all other participants in the multisig, in preparation to sign a message.

7. Receive from all participants their nonces for this signing session, and create a file called `public_nonces` containing all these nonces. The order of the participants is not important. For example:

```
02cf08c1684b35870f2a9231d75a1e8b9ac343f31e0622f7dac55beb195607cd170238cbaebcac547896d97bb7d2ca6af9b404e01c85652e5c1356161e13d651431b
02949a99f1a2fa58339981fa437fc763b622b0f9373bf5c60d788474ceced9cfb20220fd11a9d5fcb4a7a4b99c211b3b7e8e59ab9a764d3a0727f93b15d70482d7c8
023e2eae90e5bc2bc53cca532d438210a8908b5fb1f01977befab21f59be173e6602a209a7e4272b4606d6517338322f03a2a17b1f77d10f1ded8fec7d56dd337b1a
```

6. Create a file called `message` containing the message you wish to sign. The contents of the file are interpreted as bytes, not as a string. You can alternatively specify a filename. Then use the `sign <message filename (optional)>` command to generate a partial signature.

```
> cat message
hello world
> python3 musig2.py sign
Aggregate key:
6a3ebe79463836eeff69fffe493d3c42d8c5bbd47fcfaf40aa6a6026c45ab535
Signature R:
f65afa33eecff5bd837bd218075f4d4074c03eadd65e78dbd3cc66e2f55f10cd
Partial signature s_1:
fbf8fa92eda16cbac787187d8d38430e1234b1f08d8a5304a063e02bb3140808
```

This will delete the secret nonces previous generated to ensure they are not reused. The aggregate key, `R` value, and your partial signature `s_1` will be written to `message.partsig` (or correspondingly for the filename specified) though, in case you forget to copy it from the command line output.

7. Send the partial signature `s_1` to all other parties and receive their partial signatures. Create a file called `s_values` containing all these partial signatures, including your own (order does not matter):

```
fbf8fa92eda16cbac787187d8d38430e1234b1f08d8a5304a063e02bb3140808
786fab4e32625eec618ab64c4bb9c080b02d57df867bd4364a7739dd8446eb31
423773284754d75f2f807e57b6a50648f481dc380908b31f5e92c5c7d6996ebf
```

8. Aggregate the partial signatures:

```
> python3 musig2.py aggregatesignature
Hex-encoded signature: f65afa33eecff5bd837bd218075f4d4074c03eadd65e78dbd3cc66e2f55f10cdb6a019096758a30658924d218f9709d8fc3509216dc63a1e899b81443dbe20b7
```

Again, you can optionally specify the filename of the message being signed if you did not use the default `message`.

9. Verify the signature created:

```
> python3 musig2.py verify 6a3ebe79463836eeff69fffe493d3c42d8c5bbd47fcfaf40aa6a6026c45ab535 f65afa33eecff5bd837bd218075f4d4074c03eadd65e78dbd3cc66e2f55f10cdb6a019096758a30658924d218f9709d8fc3509216dc63a1e899b81443dbe20b7
Signature is valid: True
```

The format for the verification command is
`verify <public key> <signature> <message filename (optional)`

## Testing

This repository includes two types of tests. The unit tests are run on specific functions to ensure individual components are working correctly.
```
> python3 unit_tests.py
test_seckey_gen PASSED
test_read_write_bytes PASSED
test_point_serialisation PASSED
test_aggregate_public_keys PASSED
test_aggregate_nonces PASSED
test_compute_R PASSED
test_compute_s PASSED
```

The functional tests run the code externally simulating multiple users in a key establishment and signing session.
```
> python3 functional_test.py
X: ac4a3b78a1368de26f96346cdf87149a2e2d6201b14559120f73c78b1b8253c3
S: 3d18300bbcac308f7f860cc263fe0cafd8a54c0b0a18c953b3f5884dd5012e03bcc45d03cab195223bc6bf98f85f7a4ac33a29eb1d46faac172aec9649cfa678
Signature is valid: True
```
