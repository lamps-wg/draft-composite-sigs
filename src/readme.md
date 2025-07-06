# Requirements

## python
There is a python sub-component, it requires python3, pip, and venv:

1. Create a virtual environment
    ```shell
    python -m venv venv
    ```
2. Activate the virtual environment
    ```shell
    source venv/bin/activate
    ```
3. Install the dependencies

    ```shell
    pip install -r requirements.txt
    ```

## ML-DSA and ML-KEM

https://github.com/GiacomoPope/dilithium-py




# Output

The output format is intended to be reminiscent of the NIST ACVP KAT JSON format.

The message signed is the bytes of the string "The quick brown fox jumps over the lazy dog."

`ctx` is the default value of empty string.

```
{
    "m": "message"
    "tests": [
        {
          "tcId": "<composite_oid_name>",
          "pk": "<raw_key>",
          "x5c": "<x509_cert_of_pk>",
          "sk": "<sk>",
          "sk_pkcs8": <PrivateKeyInfo>
          "s": "<signature>"
        },
        ...
    ]
}
```

The ekx5c is an X.509 certificate containing the KEM key and signed by a CA cert which is common to all tests.