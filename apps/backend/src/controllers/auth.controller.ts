import type { Request, Response } from "express";
import { prisma } from "@cubik/database";
import { web3 } from "@coral-xyz/anchor";
import { createToken, decodeToken, verifyMessage } from "utils/auth";
import type { AuthCheckReturn } from "types/auth";

export const check = async (req: Request, res: Response) => {
  try {
    const { wallet } = req.body;

    const authCookie = req.cookies["authToken"];

    let returnData: AuthCheckReturn = {
      data: null,
      error: null,
    };

    if (!authCookie) {
      const user = await prisma.user.findFirst({
        where: {
          mainWallet: wallet as string,
        },
      });
      // no user then add a user
      if (!user) {
        await prisma.user.create({
          data: {
            mainWallet: wallet as string,
          },
        });
        returnData = {
          data: {
            type: "NEW_WALLET",
          },
          error: null,
        };
        return res.status(200).json(returnData);
      }
      // user exists and create one
      if (user && !user?.username) {
        returnData = {
          data: {
            type: "EXISTING_WALLET",
          },
          error: null,
        };
        return res.json(returnData); // user wallet not created
      }
      returnData = {
        data: {
          type: "USER_FOUND",
        },
        error: null,
      };

      return res.json(returnData);
    } else {
      const decodedToken = await decodeToken(authCookie.value);
      if (!decodedToken || decodedToken.mainWallet !== wallet) {
        return res
          .json({
            data: null,
            error: "INVALID_TOKEN",
          })
          .clearCookie("authToken");
      }
      returnData = {
        data: {
          type: "AUTHENTICATED_USER",
          accessToken: authCookie.value,
        },
        error: null,
      };
      return res.json(returnData);
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      data: null,
      error: "INTERNAL_SERVER_ERROR",
    });
  }
};

export const logout = async (req: Request, res: Response) => {
  try {
    return res
      .json({
        message: "Logged out successfully",
      })
      .clearCookie("authToken");
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Something went wrong",
    });
  }
};

export const verify = async (req: Request, res: Response) => {
  try {
    const { signature, publicKey } = req.body;

    // get nonce from headers
    const nonce = req.headers["x-cubik-nonce"] as string;

    const result = verifyMessage(
      signature,
      new web3.PublicKey(publicKey),
      nonce
    );

    if (result) {
      const user = await prisma.user.findUnique({
        where: {
          mainWallet: publicKey,
        },
      });
      if (!user) {
        return res.status(404).json({
          data: false,
          error: "User not found",
        });
      }

      const session = await createToken({
        ip: "test",
        mainWallet: publicKey,
        id: user.id,
        profilePicture: user.profilePicture as string,
        username: user.username as string,
        profileNft: user.profileNft as any,
      });
      const response = res.json({
        data: result,
        accessToken: session,
        error: null,
      });
      response.cookie("authToken", session as string, {
        expires: new Date(Date.now() + 3600000),
        secure: true,
        httpOnly: true,
        sameSite: "strict",
        path: "/",
      });

      return response;
    } else {
      return res.json({
        data: result,
        error: "Error verifying signature",
      });
    }
  } catch (error) {
    console.log(error);
    res.status(505).json({
      data: false,
      error: "Error verifying signature",
    });
  }
};
