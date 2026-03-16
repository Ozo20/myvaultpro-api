import { NextRequest, NextResponse } from "next/server";
import { redis } from "@/lib/redis";
import {
  buildOtpRedisKey,
  getOtpMaxAttempts,
  hashOtpCode,
  isValidEmail,
  normalizeEmail,
  type StoredOtpRecord,
} from "@/lib/otp";

type VerifyCodeRequest = {
  email?: string;
  code?: string;
};

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as VerifyCodeRequest;
    const email = normalizeEmail(body.email ?? "");
    const code = String(body.code ?? "").trim();

    if (!email || !isValidEmail(email)) {
      return NextResponse.json(
        {
          ok: false,
          errorCode: "INVALID_EMAIL",
          message: "Please provide a valid email address.",
        },
        { status: 400 }
      );
    }

    if (!/^\d{6}$/.test(code)) {
      return NextResponse.json(
        {
          ok: false,
          errorCode: "INVALID_CODE_FORMAT",
          message: "Please provide a valid 6-digit code.",
        },
        { status: 400 }
      );
    }

    const key = buildOtpRedisKey(email);
    const record = await redis.get<StoredOtpRecord>(key);

    console.log("OTP verify lookup", { email, key, record });

    if (!record) {
      return NextResponse.json(
        {
          ok: false,
          errorCode: "NO_PENDING_VERIFICATION",
          message: "No pending verification was found for this email.",
        },
        { status: 404 }
      );
    }

    const now = Date.now();

    if (record.expiresAt <= now) {
      await redis.del(key);
      return NextResponse.json(
        {
          ok: false,
          errorCode: "CODE_EXPIRED",
          message: "The verification code has expired.",
        },
        { status: 410 }
      );
    }

    const maxAttempts = record.maxAttempts || getOtpMaxAttempts();

    if (record.attemptCount >= maxAttempts) {
      await redis.del(key);
      return NextResponse.json(
        {
          ok: false,
          errorCode: "TOO_MANY_ATTEMPTS",
          message: "Too many incorrect attempts. Please request a new code.",
        },
        { status: 429 }
      );
    }

    const incomingHash = hashOtpCode(code);

    if (incomingHash !== record.codeHash) {
      const updatedAttemptCount = record.attemptCount + 1;
      const ttlSeconds = Math.max(1, Math.ceil((record.expiresAt - now) / 1000));

      const updatedRecord: StoredOtpRecord = {
        ...record,
        attemptCount: updatedAttemptCount,
      };

      await redis.set(key, updatedRecord, { ex: ttlSeconds });

      return NextResponse.json(
        {
          ok: false,
          errorCode: updatedAttemptCount >= maxAttempts ? "TOO_MANY_ATTEMPTS" : "INVALID_CODE",
          message:
            updatedAttemptCount >= maxAttempts
              ? "Too many incorrect attempts. Please request a new code."
              : "The verification code is incorrect.",
          attemptsRemaining: Math.max(0, maxAttempts - updatedAttemptCount),
        },
        { status: updatedAttemptCount >= maxAttempts ? 429 : 400 }
      );
    }

    await redis.del(key);

    return NextResponse.json({
      ok: true,
      verified: true,
      verifiedAt: new Date().toISOString(),
      email,
    });
  } catch (error) {
    console.error("verify-code error", error);

    return NextResponse.json(
      {
        ok: false,
        errorCode: "SERVER_ERROR",
        message: "Unable to verify code.",
      },
      { status: 500 }
    );
  }
}