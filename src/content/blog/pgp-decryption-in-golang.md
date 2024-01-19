---
title: "PGP Decryption in Golang"
description: "Decrypting PGP messages in Golang"
pubDate: "Jan 18 2024 09:55:00 GMT+0800"
---

Recently, one of my tasks at work was to decrypt a PGP message in a programatical way. I chose to use Golang for this task, and here is some findings I made.

There is a library called [golang.org/x/crypto/openpgp](https://golang.org/x/crypto/openpgp) that we can use to encrypt or decrypt PGP messages. However, it is being deprecated and only security fixes will be provided. For this task, newer features are not needed, so we can proceed with this library.

## The situation

We will share the public key with the receiver, and the receiver will encrypt the data with the public key and return it to us. We will then decrypt the data with our private key.

We will export the public key and private key from GPG in armored ASCII format. The public key will be shared with the receiver, and the private key will also be placed in some remote server with the Golang program for decryption.

```bash
# Export public key
gpg --armor --export <key-id> > public.key
# Export private key
gpg --armor --export-secret-keys <key-id> > private.key
```

## Initial approach

The initial approach is logical. We read the private key from a file, read the armored key ring with `openpgp.ReadArmoredKeyRing`, and then use the `Decrypt` function to decrypt the message.

```go
package main

import (
    "os"

    "golang.org/x/crypto/openpgp"
)

func main() {
    // assume the private key is in the same directory as the program
    f, err := os.Open("private.key")
    if err != nil {
        panic(err)
    }
    defer f.Close()

    // because it is in armored ASCII format, we need to use the ReadArmoredKeyRing function
    kr, err := openpgp.ReadArmoredKeyRing(f)
    if err != nil {
        panic(err)
    }

    // assume the encrypted message is in the same directory as the program
    df, err := os.Open("encrypted.txt")
    if err != nil {
        panic(err)
    }
    defer df.Close()

    // decrypt the message
    md, err := openpgp.ReadMessage(df, kr, nil, nil)
    if err != nil {
        panic(err) // panic: openpgp: openpgp.ReadMessage tag byte does not have MSB set
    }
}
```

However, this will result in an error `panic: openpgp: openpgp.ReadMessage tag byte does not have MSB set`.

After several trials, I found out that the private key may need to be decrypted first before it can be used to decrypt the message. So, I tried to decrypt the private key first with the passphrase we've set when we created the key.

```go
package main

import (
    "os"

    "golang.org/x/crypto/openpgp"
)

func main() {
    // omit for brevity

    kr, err := openpgp.ReadArmoredKeyRing(f)
    if err != nil {
        panic(err)
    }

    // decrypt the private key
    for _, k := range kr {
        err := k.PrivateKey.Decrypt([]byte("passphrase"))
        if err != nil {
            println(err.Error())
        }
        for _, subkey := range k.Subkeys {
            err := subkey.PrivateKey.Decrypt([]byte("passphrase"))
            if err != nil {
                println(err.Error())
            }
        }
    }

    // omit for brevity
}
```

Well, this still doesn't work. The error is still the same. But then, I figured maybe the message itself could be in armored format, so I tried to use `openpgp/armor` package and the `armor.Decode` function to decode the message before decrypting it.

```go
package main

import (
    "os"

    "golang.org/x/crypto/openpgp"
    "golang.org/x/crypto/openpgp/armor"
)

func main() {
    // omit for brevity

    kr, err := openpgp.ReadArmoredKeyRing(f)
    if err != nil {
        panic(err)
    }

    // decrypt the private key
    for _, k := range kr {
        err := k.PrivateKey.Decrypt([]byte("passphrase"))
        if err != nil {
            println(err.Error())
        }
        for _, subkey := range k.Subkeys {
            err := subkey.PrivateKey.Decrypt([]byte("passphrase"))
            if err != nil {
                println(err.Error())
            }
        }
    }

    df, err := os.Open("encrypted.txt")
    if err != nil {
        panic(err)
    }
    defer df.Close()

    am, err := armor.Decode(df)
    if err != nil {
        panic(err)
    }

    md, err := openpgp.ReadMessage(am.Body, kr, nil, nil)
    if err != nil {
        panic(err)
    }

    // omit for brevity
}
```

With this, we're finally able to decrypt the message without any error. However, we will need to grab the output from `md` to verify its content. For this, we can do something like this:

```go
func main() {
    // omit for brevity
    bb, err := io.ReadAll(md.UnverifiedBody)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(bb))
}
```

We're finally getting `Hello world!` as the output.

## Conclusion

1. The private key needs to be decrypted first before it can be used to decrypt the message.
2. The message may be in armored format, so we need to decode it first before decrypting it.

## Future work

We may also verify its signature after decrypting the message to ensure that the message is not tampered with.
