import { jwtVerify, SignJWT } from "jose";
import type { AuthPayload, AuthTokenCheckReturn } from "types/auth";
import nacl from "tweetnacl";
import * as anchor from "@coral-xyz/anchor";

export const decodeToken = async (
  token: string
): Promise<AuthPayload | null> => {
  try {
    const secret = new TextEncoder().encode(process.env.NEXT_PUBLIC_SECRET);
    const decodedToken = await jwtVerify(token, secret, {
      algorithms: ["HS256"],
    });

    if (!decodedToken) {
      return null;
    }

    return decodedToken.payload as AuthPayload;
  } catch (error) {
    console.log(error);
    return null;
  }
};

export const createToken = async (tokenPayload: AuthPayload) => {
  try {
    const secret = new TextEncoder().encode(process.env.NEXT_PUBLIC_SECRET);
    const alg = "HS256";
    const token = new SignJWT(tokenPayload)
      .setProtectedHeader({ alg })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(secret);

    return token;
  } catch (error) {
    console.log(error);
    return null;
  }
};

export const handleLogout = async () => {
  try {
    await fetch("/api/v1/auth/logout", {
      method: "POST",
      cache: "no-cache",
    });
    return "success";
  } catch (error) {
    console.log(error);
    return null;
  }
};

export const getToken = async () => {
  try {
    const res = await fetch("/api/v1/auth/token", {
      cache: "no-cache",
      method: "GET",
    });
    const data = (await res.json()) as AuthTokenCheckReturn;
    if (data.error ?? !data.data) {
      return null;
    }
    return data.data;
  } catch (error) {
    console.log(error);
    return null;
  }
};

export const createMessage = (nonce: string) => {
  const hash = nonce + process.env.NEXT_PUBLIC_SECRET?.slice(0, 10);
  const check = anchor.utils.sha256.hash(hash);
  const message = `🔶 Welcome to Cubik! 🔶\n
-----------------------------\n
🌱 Dive into a realm where every voice fuels projects, \n
breathing life into ideas with the power of community. 🌱 \n
session: ${check}\n`;

  const data = new TextEncoder().encode(message);

  return data;
};

export const verifyMessage = (
  signature: string,
  publicKey: anchor.web3.PublicKey,
  nonce: string
) => {
  const message = createMessage(nonce);
  const result = nacl.sign.detached.verify(
    message,
    anchor.utils.bytes.bs58.decode(signature),
    publicKey.toBuffer()
  );
  return result;
};
