#! /usr/bin/env python3

import json
import os
import subprocess
from os import path

HERE = path.dirname(path.abspath(__file__))
os.chdir(HERE)


def test_input(length):
    ret = bytearray()
    for i in range(length):
        ret.append(i % 251)
    return ret


def test_run(input_len, flags):
    return (
        subprocess.run(
            ["./blake3"] + flags,
            input=test_input(input_len),
            stdout=subprocess.PIPE,
            check=True,
        )
        .stdout.decode()
        .strip()
    )


def main():
    build_cmd = [
        "gcc",
        "reference_impl.c",
        "-g",
        "-pedantic",
        "-Wall",
        "-Werror",
        "-o",
        "blake3",
        "-fsanitize=address,undefined",
    ]
    print(" ".join(build_cmd))
    subprocess.run(build_cmd, check=True)

    with open("test_vectors.json") as f:
        vectors = json.load(f)
    test_key = vectors["key"].encode()
    test_context = vectors["context_string"]
    for case in vectors["cases"]:
        input_len = case["input_len"]
        print("input length:", input_len)

        # regular hashing
        assert test_run(input_len, []) == case["hash"][:64]
        assert test_run(input_len, ["--len", "131"]) == case["hash"]

        # keyed hashing
        assert test_run(input_len, ["--key", test_key.hex()]) == case["keyed_hash"][:64]
        assert (
            test_run(input_len, ["--key", test_key.hex(), "--len", "131"])
            == case["keyed_hash"]
        )

        # key derivation
        assert (
            test_run(input_len, ["--derive-key", test_context])
            == case["derive_key"][:64]
        )
        assert (
            test_run(input_len, ["--derive-key", test_context, "--len", "131"])
            == case["derive_key"]
        )

    print("TESTS PASSED")


if __name__ == "__main__":
    main()
