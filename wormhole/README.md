# Luna Wormhole

A tiny bidirectional bridge using the GitHub repository as a persistent message board.

## Flow

Luna writes a command to:

    wormhole/inbox/<command-id>.json

The Raspberry Pi polls the public repository, executes the small set of allowed operations, and writes the response to:

    wormhole/outbox/<command-id>.json

Luna then reads the response from GitHub.

For the first test the only operation is:

    ping

Expected response:

    PONG FROM RASPBERRY PI

## Pi setup

1. Copy `pi_wormhole.py` to the Raspberry Pi.
2. Create a GitHub token with permission to write contents to the `mick2812/luna` repository.
3. Put the token in the environment as `GITHUB_TOKEN`.
4. Run:

    python3 pi_wormhole.py

The script keeps a local state file so commands are processed once.

The Pi never exposes a new network port. It only makes outbound HTTPS requests to GitHub.

## Security boundary

The inbox is treated as untrusted input. The first version deliberately supports only `ping`; do not add arbitrary shell execution to the command dispatcher.
