// @ts-nocheck
import type { NextRequest } from "next/server";

interface HandshakeRequest {
	client_name?: string;
	client_version?: string;
	device_id?: string;
	timestamp?: string;
}

interface HandshakeResponse {
	status: string;
	session_token?: string;
	server_version?: string;
	message?: string;
}

export async function POST(request: NextRequest) {
	const body = (await request.json()) as HandshakeRequest;
	const { client_name, client_version, device_id, timestamp } = body;

	// demo
	const authorizedDevices = new Set([
		"dev1",
	]);

	if (!device_id || !authorizedDevices.has(device_id)) {
		console.log("Unauthorized device attempted handshake:", {
			device_id,
			client_name,
			remote_addr:
				request.headers.get("x-forwarded-for") ||
				request.headers.get("x-real-ip") ||
				"unknown",
		});
		return Response.json(
			{
				status: "error",
				message: "Device not authorized",
			},
			{ status: 401 },
		);
	}

	// example
	const sessionToken = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

	console.log("Handshake successful:", {
		device_id,
		client_name,
		client_version,
		timestamp,
		session_token: sessionToken,
		remote_addr:
			request.headers.get("x-forwarded-for") ||
			request.headers.get("x-real-ip") ||
			"unknown",
	});

	const response: HandshakeResponse = {
		status: "ok",
		session_token: sessionToken,
		server_version: "1.0.0",
		message: `ok`,
	};

	return Response.json(response, { status: 200 });
}
