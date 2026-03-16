import { NextRequest, NextResponse } from "next/server";
import { Resend } from "resend";
import { redis } from "@/lib/redis";
import {
  buildOtpRedisKey,
  generateOtpCode,
  getOtpExpirySeconds,
  getOtpMaxAttempts,
  getOtpResendCooldownSeconds,
  hashOtpCode,
  isValidEmail,
  maskEmail,
  normalizeEmail,
  type StoredOtpRecord,
} from "@/lib/otp";

const resend = new Resend(process.env.RESEND_API_KEY);

type SendCodeRequest = {
  email?: string;
  displayName?: string;
};

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as SendCodeRequest;
    const email = normalizeEmail(body.email ?? "");

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

    const key = buildOtpRedisKey(email);
    const now = Date.now();
    const cooldownMs = getOtpResendCooldownSeconds() * 1000;
    const existing = await redis.get<StoredOtpRecord>(key);

    console.log("OTP existing record", {
      email,
      key,
      existing,
      now,
      cooldownMs,
    });

    if (existing && now - existing.lastSentAt < cooldownMs) {
      return NextResponse.json(
        {
          ok: false,
          errorCode: "RATE_LIMITED",
          message: "Please wait before requesting a new code.",
        },
        { status: 429 }
      );
    }

    const code = generateOtpCode();
    const expiresInSeconds = getOtpExpirySeconds();

    const record: StoredOtpRecord = {
      email,
      codeHash: hashOtpCode(code),
      createdAt: now,
      lastSentAt: now,
      expiresAt: now + expiresInSeconds * 1000,
      attemptCount: 0,
      maxAttempts: getOtpMaxAttempts(),
    };

    await redis.set(key, record, { ex: expiresInSeconds });

    const stored = await redis.get<StoredOtpRecord>(key);
    console.log("OTP stored record", { email, key, stored });

    const from = process.env.EMAIL_FROM;
    const replyTo = process.env.EMAIL_REPLY_TO;

    if (!from) {
      return NextResponse.json(
        {
          ok: false,
          errorCode: "SERVER_ERROR",
          message: "Missing EMAIL_FROM configuration.",
        },
        { status: 500 }
      );
    }

    const { data, error } = await resend.emails.send({
      from,
      to: email,
      replyTo: replyTo || undefined,
      subject: "Your MyVaultPro verification code",
      text: [
        `Your MyVaultPro verification code is: ${code}`,
        "",
        `This code expires in ${Math.floor(expiresInSeconds / 60)} minutes.`,
        "",
        "If you did not request this code, you can ignore this email.",
      ].join("\n"),
    });

    console.log("Resend send result", { data, error, email, from, replyTo });

    if (error) {
      console.error("Resend send error", error);
      return NextResponse.json(
        {
          ok: false,
          errorCode: "EMAIL_SEND_FAILED",
          message: "Unable to send verification email.",
        },
        { status: 502 }
      );
    }

    return NextResponse.json({
      ok: true,
      expiresInSeconds,
      cooldownSeconds: getOtpResendCooldownSeconds(),
      maskedEmail: maskEmail(email),
    });
  } catch (error) {
    console.error("send-code error", error);

    return NextResponse.json(
      {
        ok: false,
        errorCode: "SERVER_ERROR",
        message: "Unable to send verification code.",
      },
      { status: 500 }
    );
  }
}