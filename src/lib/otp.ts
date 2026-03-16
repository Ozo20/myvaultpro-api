import crypto from "crypto";

const OTP_LENGTH = Number(process.env.OTP_LENGTH ?? 6);
const OTP_EXPIRY_SECONDS = Number(process.env.OTP_EXPIRY_SECONDS ?? 900);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS ?? 5);
const OTP_RESEND_COOLDOWN_SECONDS = Number(
  process.env.OTP_RESEND_COOLDOWN_SECONDS ?? 60
);

export type StoredOtpRecord = {
  email: string;
  codeHash: string;
  expiresAt: number;
  createdAt: number;
  lastSentAt: number;
  attemptCount: number;
  maxAttempts: number;
};

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function generateOtpCode(length = OTP_LENGTH): string {
  const min = Math.pow(10, length - 1);
  const max = Math.pow(10, length) - 1;
  const value = crypto.randomInt(min, max + 1);
  return String(value);
}

export function hashOtpCode(code: string): string {
  return crypto.createHash("sha256").update(code).digest("hex");
}

export function getOtpExpirySeconds(): number {
  return OTP_EXPIRY_SECONDS;
}

export function getOtpMaxAttempts(): number {
  return OTP_MAX_ATTEMPTS;
}

export function getOtpResendCooldownSeconds(): number {
  return OTP_RESEND_COOLDOWN_SECONDS;
}

export function maskEmail(email: string): string {
  const [local, domain] = email.split("@");
  if (!local || !domain) return email;
  if (local.length <= 2) return `${local[0] ?? "*"}*@${domain}`;
  return `${local[0]}${"*".repeat(Math.max(1, local.length - 2))}${local.at(-1)}@${domain}`;
}

export function buildOtpRedisKey(email: string): string {
  return `otp:${normalizeEmail(email)}`;
}
