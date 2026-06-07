#!/bin/bash
# Debug keypair mismatch

echo "=== Keypair Debug Script ==="
echo

# 1. Extract public key from the production private key
echo "1. Public key from core/assets/signing_key.pem:"
PUB_FROM_PEM=$(openssl pkey -in core/assets/signing_key.pem -pubout -outform DER 2>/dev/null | tail -c 32 | base64)
echo "   $PUB_FROM_PEM"
echo

# 2. Check if signing_key.pub fallback exists
echo "2. Fallback file (core/assets/signing_key.pub):"
if [ -f "core/assets/signing_key.pub" ]; then
    cat core/assets/signing_key.pub
    echo "   (File exists - may be used if TUORA_SIGNING_PUBKEY not set)"
else
    echo "   (File does not exist - OK)"
fi
echo

# 3. Extract embedded key from compiled binary
echo "3. Checking compiled binary for embedded key..."
if [ -f "target/release/tuora" ]; then
    # Try to find base64 strings that look like Ed25519 public keys (44 chars ending in =)
    echo "   Searching target/release/tuora..."
    strings target/release/tuora | grep -E "^[A-Za-z0-9+/]{43}=$" | head -5 | while read line; do
        # Verify it's 32 bytes when decoded
        decoded=$(echo "$line" | base64 -d 2>/dev/null | wc -c)
        if [ "$decoded" = "32" ]; then
            echo "   Found: $line (32 bytes decoded)"
        fi
    done
elif [ -f "target/debug/tuora" ]; then
    echo "   Searching target/debug/tuora..."
    strings target/debug/tuora | grep -E "^[A-Za-z0-9+/]{43}=$" | head -5 | while read line; do
        decoded=$(echo "$line" | base64 -d 2>/dev/null | wc -c)
        if [ "$decoded" = "32" ]; then
            echo "   Found: $line (32 bytes decoded)"
        fi
    done
else
    echo "   No compiled binary found"
fi
echo

# 4. Compare
echo "4. Comparison:"
echo "   From PEM:  $PUB_FROM_PEM"
echo
if [ -n "$TUORA_SIGNING_PUBKEY" ]; then
    echo "   From env:  $TUORA_SIGNING_PUBKEY"
    if [ "$PUB_FROM_PEM" = "$TUORA_SIGNING_PUBKEY" ]; then
        echo "   ✓ MATCH!"
    else
        echo "   ✗ MISMATCH!"
    fi
else
    echo "   From env:  (not set - will use fallback file or empty)"
fi
echo

# 5. Test signing locally
echo "5. Local signing test:"
echo "test message" > /tmp/test_msg.txt
if openssl pkeyutl -sign -in /tmp/test_msg.txt -inkey core/assets/signing_key.pem -out /tmp/test_sig.bin 2>/dev/null; then
    echo "   ✓ Sign: SUCCESS"
    
    # Extract raw public key for verification
    openssl pkey -in core/assets/signing_key.pem -pubout -outform DER 2>/dev/null | tail -c 32 > /tmp/test_pub.raw
    
    # Try to verify with openssl
    if openssl pkeyutl -verify -sigfile /tmp/test_sig.bin -in /tmp/test_msg.txt -inkey core/assets/signing_key.pem -pubin 2>/dev/null; then
        echo "   ✓ Verify: SUCCESS"
    else
        echo "   ✗ Verify: FAILED"
    fi
else
    echo "   ✗ Sign: FAILED"
fi

echo
echo "=== End Debug ==="
