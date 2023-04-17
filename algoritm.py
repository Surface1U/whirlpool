WORD_SIZE = 8  # 64 bits
BLOCK_SIZE = 64  # 512 bits
ROUNDS = 10
SBOX_SIZE = 256
SBOX = [[0] * SBOX_SIZE for _ in range(8)]
PI = [0] * WORD_SIZE * 8
RC = [0] * ROUNDS

# Initialize the constants
def init():
    # S-box
    p = 1
    for i in range(8):
        for j in range(SBOX_SIZE):
            v = p
            for _ in range(8):
                v ^= (v >> 8)
            SBOX[i][j] = v
            p = (p << 1) ^ (0x11B if (p & 0x80) else 0)

    # PI permutation
    for i in range(WORD_SIZE * 8):
        PI[i] = (8 * (i % WORD_SIZE)) + (i // WORD_SIZE)

    # Round constants
    RC[0] = 1
    for i in range(1, ROUNDS):
        RC[i] = (RC[i-1] << 1) ^ (0x11B if (RC[i-1] & 0x80) else 0)

# Whirlpool hash function
def whirlpool(message):
    # Initialize the constants
    init()

    # Convert the message to a byte string if necessary
    if not isinstance(message, bytes):
        message = message.encode()

    # Initialize the hash values
    H = [0] * 8

    # Process each block
    for i in range(0, len(message), BLOCK_SIZE):
        # Pad the block with zeros if necessary
        block = message[i:i+BLOCK_SIZE]
        if len(block) < BLOCK_SIZE:
            block += b'\x00' * (BLOCK_SIZE - len(block))

        # XOR the block with the hash values
        x = [int.from_bytes(block[j:j+WORD_SIZE], 'big') ^ H[j] for j in range(8)]

        # Apply the round function ROUNDS times
        for r in range(ROUNDS):
            # Apply the substitution box
            y = [0] * 8
            for j in range(8):
                if x[j] < 0 or x[j] >= SBOX_SIZE:
                    raise ValueError("Invalid value of x[j]")
                y[j] = SBOX[j][x[j]]

            # Apply the permutation
            z = [0] * 8
            for j in range(WORD_SIZE):
                for k in range(8):
                    z[k] |= ((y[k*WORD_SIZE+j] >> (WORD_SIZE-1-i)) & 1) << (WORD_SIZE-1-j)

            # XOR the round constant with the first word
            z[0] ^= RC[r]

            # Update the input and output variables for the next round
            x = z
            z = y

        # XOR the block with the input variables
        H = [(H[j] ^ x[j]) for j in range(8)]

    # Convert the hash values to a byte string
    return b''.join([H[j].to_bytes(WORD_SIZE, 'big') for j in range(8)])

message = b'This is a test message'
if len(message) % BLOCK_SIZE != 0:
    message += b'\x00' * (BLOCK_SIZE - len(message) % BLOCK_SIZE)

# Compute the hash value of the message
hash_value = whirlpool(message)
print(hash_value.hex())
