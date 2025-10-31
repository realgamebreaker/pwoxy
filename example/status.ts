// @ts-nocheck
import {
	constants,
	createDecipheriv,
	createHash,
	createPrivateKey,
	privateDecrypt,
} from "crypto";
import type { NextRequest } from "next/server";

interface Payload {
	hash_sha256?: string;
	encrypted_key_base64?: string;
	nonce_base64?: string;
	tag_base64?: string;
	ciphertext_base64?: string;
}

export async function POST(request: NextRequest) {
	// check for session token
	const authHeader = request.headers.get("authorization");
	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return Response.json(
			{
				status: "error",
				message: "Missing or invalid authorization header",
			},
			{ status: 401 },
		);
	}

	const sessionToken = authHeader.substring(7); // remove "Bearer " prefix

	// Basic validation. The server would compare this against a database
	if (!sessionToken.startsWith("session_")) {
		return Response.json(
			{
				status: "error",
				message: "Invalid session token",
			},
			{ status: 401 },
		);
	}

	const privateKeyPem = process.env.SERVER_PRIVATE_KEY;
	if (!privateKeyPem) {
		return Response.json(
			{
				status: "error",
				message: "SERVER_PRIVATE_KEY is not configured",
			},
			{ status: 500 },
		);
	}

	const body = (await request.json()) as Payload;
	const {
		hash_sha256,
		encrypted_key_base64,
		nonce_base64,
		tag_base64,
		ciphertext_base64,
	} = body;
	if (
		!hash_sha256 ||
		!encrypted_key_base64 ||
		!nonce_base64 ||
		!tag_base64 ||
		!ciphertext_base64
	) {
		return Response.json(
			{
				status: "error",
				message: "Missing encryption fields",
			},
			{ status: 400 },
		);
	}

	try {
		const privateKey = createPrivateKey({ key: privateKeyPem });

		const encryptedKey = Buffer.from(encrypted_key_base64, "base64");
		const symmetricKey = privateDecrypt(
			{
				key: privateKey,
				padding: constants.RSA_PKCS1_OAEP_PADDING,
				oaepHash: "sha256",
			},
			encryptedKey,
		);

		if (symmetricKey.length !== 32) {
			return Response.json(
				{
					status: "error",
					message: "Invalid symmetric key",
				},
				{ status: 400 },
			);
		}

		const nonce = Buffer.from(nonce_base64, "base64");
		const tag = Buffer.from(tag_base64, "base64");
		const ciphertext = Buffer.from(ciphertext_base64, "base64");

		const decipher = createDecipheriv("aes-256-gcm", symmetricKey, nonce);
		decipher.setAuthTag(tag);
		const decryptedBuffer = Buffer.concat([
			decipher.update(ciphertext),
			decipher.final(),
		]);

		// verify integrity of the decrypted payload
		const computedHash = createHash("sha256")
			.update(decryptedBuffer)
			.digest("hex");
		if (computedHash !== hash_sha256.toLowerCase()) {
			return Response.json(
				{
					status: "error",
					message: "Hash verification failed",
				},
				{ status: 400 },
			);
		}

		const decryptedData = JSON.parse(decryptedBuffer.toString("utf-8"));

		return Response.json({ status: "ok", decryptedData }, { status: 200 });
	} catch (error) {
		console.error("Failed to process incoming payload", error);
		return Response.json(
			{
				status: "error",
				message: "Invalid payload",
			},
			{ status: 400 },
		);
	}
}
