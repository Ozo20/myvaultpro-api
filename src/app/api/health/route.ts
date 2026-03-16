import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json({
    ok: true,
    env: {
      hasResendKey: Boolean(process.env.RESEND_API_KEY),
      hasRedisUrl: Boolean(process.env.UPSTASH_REDIS_REST_URL),
      hasRedisToken: Boolean(process.env.UPSTASH_REDIS_REST_TOKEN),
      emailFrom: process.env.EMAIL_FROM ?? null,
      emailReplyTo: process.env.EMAIL_REPLY_TO ?? null,
    },
  });
}
