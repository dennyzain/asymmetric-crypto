import { secp256k1 as secp } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/curves/abstract/utils";

const PRIVATE_KEY = sha256("denny zain");

function hash(msg: string): Uint8Array {
  const hashing = sha256(msg);
  // console.log(hashing,"hashing")
  return hashing;
}

async function sign(msg: string, privateKey: Uint8Array) {
  const msgHashed = hash(msg);
  const signature = await secp.sign(msgHashed, privateKey);
  // console.log(signature,"signature");
  return signature;
}

async function verify(msg: string, signature: any, publicKey: Uint8Array): Promise<boolean> {
  const msgHashed = hash(msg);
  const verification = await secp.verify(signature, msgHashed, publicKey);
  // console.log(verification, "verification");
  return verification;
}

// ! get address from public key
const publicKey = secp.getPublicKey(PRIVATE_KEY);
console.log(bytesToHex(sha256(publicKey.slice(1)).slice(-20)), "public key");

// ! sign message
const signature = await sign("halo kawan", PRIVATE_KEY);
console.log(signature, "signature");

// ! verify signature
const verification = await verify("halo kawan", signature, publicKey);
console.log(verification, "verification");

// ! recover public key from signature
const recoveredPublicKey = await signature.recoverPublicKey(bytesToHex(hash("halo kawan")));
console.log(recoveredPublicKey);

// ! what is Uint8Array?
/*
	1.	Typed Array:
	•	A Uint8Array is part of the TypedArray family in JavaScript, which provides arrays for handling binary data (raw memory).
	•	Typed arrays are designed to handle binary data efficiently, which is useful for tasks like manipulating images, audio, and other types of binary data.
	2.	8-bit Unsigned Integer:
	•	Each element in a Uint8Array is an unsigned 8-bit integer, which means it can hold values from 0 to 255.
	•	“Unsigned” means that the values are always non-negative.

    */
