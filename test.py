#! /usr/bin/env python3

import json
import os
import platform
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)

if platform.system() == "Windows":
    EXE = "blake3.exe"
    BUILD_COMMAND = [
        "cl.exe",
        "reference_impl.c",
        "main.c",
        "/W4",  # display most warnings, but not those off by default
        "/WX",  # like -Werror
        "/Fe:",  # like -o
        EXE,
    ]
else:
    EXE = "./blake3"
    BUILD_COMMAND = [
        "gcc",
        "reference_impl.c",
        "main.c",
        "-g",
        "-pedantic",
        "-Wall",
        "-Werror",
        "-o",
        EXE,
        "-fsanitize=address,undefined",
    ]


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
    print(" ".join(BUILD_COMMAND))
    subprocess.run(BUILD_COMMAND, check=True)

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
