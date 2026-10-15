"""Python entry point for the Rust crypto worker fixture."""

from cffi import FFI


def main() -> None:
    ffi = FFI()
    ffi.cdef("int crypto_worker_digest(const unsigned char *input, size_t length);")
    print("waiting for crypto payloads", ffi)


if __name__ == "__main__":
    main()
