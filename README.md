# Mining Devzat ID

```
mining-devzat-id, a tool to get yourself a shiny Devzat ID.
This tool generate an openSSH ed25519 private key that will make a
cool Devzat id.

Usage:
    ./mining-devzat-id desired-id [thread-number [output-file]]
  desired-id: start of the resulting id. If desired-id is 000, you
              will get an id starting with 000 such as 000c6d33...
  thread-number: number of threads used to compute the id.
                 Default to 1.
  output-file: path to the file where the generated key will be written.
               Default to stdout.
```

