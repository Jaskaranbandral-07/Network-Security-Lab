"""
Challenge-Response Authentication using HMAC-SHA256
----------------------------------------------------
Aim: Implement challenge-response authentication using HMAC-SHA256 and
understand how nonce and timestamp mechanisms prevent replay attacks.

Methodology:
1. Establish a shared secret key between the client and server.
2. The server generates a random challenge (nonce).
3. The client uses the challenge and secret key to generate an
   HMAC-SHA256 response.
4. The server verifies the received response.
5. Repeat the authentication process to generate a new challenge.
6. Demonstrate a replay attack by reusing an old response.
7. Add timestamp/freshness checks to reject old or delayed responses.
8. Test mutual authentication using fresh challenges.
"""

import hmac        # Provides HMAC (Hash-based Message Authentication Code) functions
import hashlib     # Provides the SHA-256 hash algorithm used inside the HMAC
import secrets     # Provides cryptographically secure random number generation (for the nonce)
import time        # Used to timestamp challenges and measure elapsed time (freshness check)


class Server:
    # The Server class represents the "verifier" side: it issues challenges
    # and checks whether the client's response proves it knows the secret key.

    def __init__(self, shared_secret: str, challenge_validity: int = 30):
        # Convert the secret string into bytes because HMAC works on byte data, not text
        self.secret_key = shared_secret.encode()
        # How many seconds a challenge remains valid before it "expires" (freshness window)
        self.challenge_validity = challenge_validity
        # Stores the most recently issued challenge (nonce); starts empty
        self.current_challenge = None
        # Stores the time the current challenge was issued; used to check for delays
        self.challenge_timestamp = None
        # A set that remembers every response already accepted, so it can detect replay attempts
        self.used_responses = set()

    def generate_challenge(self) -> str:
        """Step 2: Server generates a random challenge (nonce)."""
        # secrets.token_hex(16) creates a random 32-character hex string (the nonce)
        self.current_challenge = secrets.token_hex(16)
        # Record the exact moment this challenge was created (for later expiry checking)
        self.challenge_timestamp = time.time()
        # Log the newly issued challenge so we can see it in the console output
        print(f"[Server] New challenge issued: {self.current_challenge}")
        # Return the challenge so it can be sent to the client
        return self.current_challenge

    def verify_response(self, response: str, client_timestamp: float) -> bool:
        """Step 4 & 7: Verify response, freshness, and detect replay attacks."""

        # --- Replay attack check ---
        # If this exact response was already accepted once before, reject it immediately
        if response in self.used_responses:
            print("[Server] Replay attempt: Old challenge/response reused")
            print("[Server] Result -> Authentication Rejected")
            return False  # Stop here; a replayed response is never valid

        # --- Freshness / timestamp check ---
        # Calculate how many seconds have passed since the challenge was issued
        elapsed = time.time() - self.challenge_timestamp
        # If too much time has passed, the challenge is considered stale/expired
        if elapsed > self.challenge_validity:
            print(f"[Server] Challenge expired ({elapsed:.1f}s old)")
            print("[Server] Result -> Authentication Rejected")
            return False  # Stop here; an expired challenge cannot be used

        # --- Recompute the expected response ---
        # The server independently computes what the correct HMAC-SHA256 response
        # should be, using the same challenge and the same shared secret key
        expected_response = hmac.new(
            self.secret_key,               # Key used to "sign" the challenge
            self.current_challenge.encode(),  # The challenge, converted to bytes
            hashlib.sha256                 # Hash algorithm used inside HMAC
        ).hexdigest()                       # Convert the raw digest into a readable hex string

        # --- Compare client's response with the expected one ---
        # hmac.compare_digest() does a constant-time comparison to avoid timing attacks
        if hmac.compare_digest(response, expected_response):
            # Mark this response as "used" so it can never be replayed again
            self.used_responses.add(response)
            print("[Server] Result -> Authentication Successful")
            return True  # The client proved it knows the secret key
        else:
            # The response didn't match the expected HMAC, so authentication fails
            print("[Server] Result -> Authentication Rejected (Invalid response)")
            return False


class Client:
    # The Client class represents the "prover" side: it must prove it knows
    # the shared secret without ever sending the secret itself over the network.

    def __init__(self, shared_secret: str):
        # Store the same shared secret (as bytes) that the server also has
        self.secret_key = shared_secret.encode()

    def generate_response(self, challenge: str) -> str:
        """Step 3: Client generates HMAC-SHA256 response using challenge + secret key."""
        # Compute HMAC-SHA256 over the challenge, keyed with the shared secret
        response = hmac.new(
            self.secret_key,      # Same secret key the server holds
            challenge.encode(),   # The challenge/nonce received from the server, as bytes
            hashlib.sha256        # Hash function used inside the HMAC construction
        ).hexdigest()              # Convert to a hex string so it's easy to print/transmit

        # Log the generated response for visibility in the demo
        print(f"[Client] Response -> HMAC-SHA256(challenge, secret) = {response}")
        # Send the response back to the caller (which will forward it to the server)
        return response


def run_demo():
    # Shared secret known only to the legitimate client and server (set up in advance)
    shared_secret = "super_secret_key_123"
    # Create a server instance; challenges expire after 5 seconds for demo purposes
    server = Server(shared_secret, challenge_validity=5)
    # Create a client instance that knows the same shared secret
    client = Client(shared_secret)

    # ---- First (legitimate) authentication ----
    print("\n=== First Authentication ===")
    challenge = server.generate_challenge()          # Server issues a fresh nonce
    response = client.generate_response(challenge)   # Client computes HMAC response
    old_response = response                          # Save this response to replay later (attack demo)
    server.verify_response(response, time.time())    # Server checks the response -> should succeed

    # ---- Second authentication with a fresh challenge ----
    print("\n=== Second Authentication (fresh challenge) ===")
    challenge2 = server.generate_challenge()          # A brand-new nonce is generated
    response2 = client.generate_response(challenge2)  # Client responds to the new challenge
    server.verify_response(response2, time.time())    # Should succeed since it's fresh and correct

    # ---- Step 6: Demonstrate a replay attack ----
    print("\n=== Replay Attack Demonstration ===")
    print("[Attacker] Reusing an old challenge/response...")
    # An attacker (or faulty client) resends the very first response again
    server.verify_response(old_response, time.time())  # Should be REJECTED (already used)

    # ---- Step 7: Demonstrate expired/delayed response rejection ----
    print("\n=== Delayed Response Demonstration ===")
    challenge3 = server.generate_challenge()           # Server issues another new challenge
    response3 = client.generate_response(challenge3)   # Client computes a valid response
    print("[System] Simulating network delay of 6 seconds...")
    time.sleep(6)  # Pause execution for 6 seconds, longer than the 5s validity window
    server.verify_response(response3, time.time())      # Should be REJECTED (challenge expired)


# This block only runs when the script is executed directly (not when imported as a module)
if __name__ == "__main__":
    run_demo()  # Start the full demonstration described above