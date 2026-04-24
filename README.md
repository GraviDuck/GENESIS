Bitcoin-Style Genesis Block Miner
A lightweight C++ utility designed to generate and mine the Genesis Block for custom blockchain projects based on the Bitcoin protocol.
It automatically constructs the coinbase transaction (including your custom timestamp message), calculates the Merkle Root, and performs the Proof-of-Work (PoW) to find a valid hash according to your specified difficulty (nBits).
Features
Coinbase Construction: Properly formats the coinbase transaction with a custom message (pszTimestamp).
Merkle Root Calculation: Generates the Merkle Root based on the coinbase transaction.
Proof-of-Work: Iterates through nonces until a hash meeting the target difficulty is found.
Output for Chainparams: Provides all the necessary values (nTime, nNonce, nBits, Hash, Merkle Root) to be plugged directly into your source code (typically chainparams.cpp).
Prerequisites
You will need the following libraries installed on your system:
OpenSSL: For SHA-256 hashing.
Boost: Specifically boost/multiprecision for handling large integers.
Install dependencies (Ubuntu/Debian)
bash
sudo apt-get update
sudo apt-get install libssl-dev libboost-all-dev build-essential
Usa el código con precaución.
Compilation
Use g++ with high optimization (-O3) for faster mining:
bash
g++ -O3 -std=c++17 genesis.cpp -o genesis -lcrypto
Usa el código con precaución.
Usage
The program requires four arguments:
PUBKEY: The public key (hex) where the genesis reward will be sent.
MESSAGE: The string message to include in the coinbase (e.g., a news headline).
NBITS: The difficulty target in hex format (e.g., 1d00ffff).
REWARD: The block reward amount (e.g., 50).
Example
bash
./genesis 04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks" 1d00ffff 50
Usa el código con precaución.
Output Explained
Once a valid nonce is found, the tool will output:
pszTimestamp: Your custom message.
nTime: The Unix timestamp used.
nNonce: The number that satisfied the hash target.
nBits: The difficulty level.
Merkle Root: The hash of the genesis transaction.
Genesis Hash: The final block hash (starting with zeros depending on difficulty).
License
This project is open-source. Feel free to use it for your own blockchain experiments.
