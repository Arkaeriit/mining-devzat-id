# Mining Devzat ID

```
mining-devzat-id, a tool to get yourself a shiny Devzat ID.
This tool generates an openSSH ed25519 private key that will make a
cool Devzat id or SSH pubkey.

Usage:
    ./mining-devzat-id desired-id [-j thread-number] [-o output-file] [-t type]
  desired-id: Vanity part of the resulting id. If desired-id is 000, you
              will get an id starting with 000 such as 000c6d33...
  thread-number: Number of threads used to compute the id.
                 Default to 1.
  output-file: Oath to the file where the generated key will be written.
               Default to stdout.
  type: Either 'devzat-id' to generate a key that will  make the desired
        Devzat ID or 'ssh-pubkey' to generate a key with the desired ID
        as it's pubkey sufix. Default to Devzat ID.
```

## Compilation with Cosmopolitan libc

If you want to compile it with the Cosmopolitan libc to make a portable executable, do `make mining-devzat-id.com`.

Note: this uses comopolitan v2, which is not very up to date.

