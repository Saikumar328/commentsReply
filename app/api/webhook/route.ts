import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/client";
import {
  parseCommentEvents,
  verifyWebhookSignature,
} from "@/lib/meta/webhook";
import { processInstagramWebhook } from "@/lib/queue/process-webhook";


interface RawWebhookBody {
  object?: string;
  entry?: Array<{
    id?: string;
    changes?: Array<{ field?: string }>;
    messaging?: Array<{
      postback?: unknown;
      message?: { is_echo?: boolean };
      read?: unknown;
      reaction?: unknown;
    }>;
  }>;
}

// Diagnostics only: which kinds of events are arriving (comments vs message vs
// postback ...) so a signature failure can be tied to an event class. Contains
// no secrets and no message text.
function describeWebhookBody(rawBody: string) {
  try {
    const body = JSON.parse(rawBody) as RawWebhookBody;
    const fields = new Set<string>();
    const messaging = new Set<string>();
    const entryIds: string[] = [];
    for (const entry of body.entry ?? []) {
      if (entry.id) entryIds.push(String(entry.id));
      for (const change of entry.changes ?? []) {
        if (change.field) fields.add(change.field);
      }
      for (const m of entry.messaging ?? []) {
        if (m.postback) messaging.add("postback");
        else if (m.message?.is_echo) messaging.add("message_echo");
        else if (m.message) messaging.add("message");
        else if (m.read) messaging.add("read");
        else if (m.reaction) messaging.add("reaction");
        else messaging.add("other_messaging");
      }
    }
    return {
      object: body.object ?? null,
      fields: [...fields],
      messaging: [...messaging],
      entryIds,
      // True when the body has emoji / Telugu / accents. Meta signs an
      // escaped-unicode form of such bodies (see lib/meta/webhook.ts).
      hasNonAscii: /[^\x00-\x7f]/.test(rawBody),
    };
  } catch {
    return { unparsable: true, hasNonAscii: /[^\x00-\x7f]/.test(rawBody) };
  }
}

// Diagnostics only: shape of a configured secret (never the value itself).
function describeSecret(value: string | undefined) {
  if (!value) return { configured: false };
  const trimmed = value.trim();
  return {
    configured: true,
    length: value.length,
    looksLikeHex32: /^[0-9a-f]{32}$/i.test(value),
    hasEdgeWhitespace: value !== trimmed,
    hasQuotes: /^["'`]|["'`]$/.test(trimmed),
  };
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const mode = searchParams.get("hub.mode");
  const token = searchParams.get("hub.verify_token");
  const challenge = searchParams.get("hub.challenge");

  if (mode === "subscribe" && token === process.env.WEBHOOK_VERIFY_TOKEN) {
    return new NextResponse(challenge, { status: 200 });
  }

  return NextResponse.json(
    { success: false, error: "Verification failed" },
    { status: 403 }
  );
}

export async function POST(request: NextRequest) {
  const rawBody = await request.text();
  const signature = request.headers.get("x-hub-signature-256");

  if (!verifyWebhookSignature(rawBody, signature)) {
    const description = describeWebhookBody(rawBody);
    const secrets = {
      facebook: describeSecret(process.env.FACEBOOK_APP_SECRET),
      instagram: describeSecret(process.env.INSTAGRAM_APP_SECRET),
    };
    const signatureFormatOk = /^sha256=[0-9a-f]{64}$/i.test(signature ?? "");
    console.warn(
      "[webhook] signature FAILED",
      JSON.stringify({ ...description, secrets, signatureFormatOk })
    );
    // Record the attempt so a signature mismatch is visible rather than a
    // silent 401. This is the common symptom of FACEBOOK_APP_SECRET being
    // set to the wrong app's secret for the webhook's signing key.
    await prisma.operationalEvent
      .create({
        data: {
          source: "SYSTEM",
          level: "WARNING",
          message: "Webhook signature verification failed",
          payload: {
            hadSignatureHeader: Boolean(signature),
            bodyLength: rawBody.length,
            bodyPreview: rawBody.slice(0, 200),
            ...description,
            secrets,
            signatureFormatOk,
          },
        },
      })
      .catch(() => {});
    return NextResponse.json(
      { success: false, error: "Invalid signature" },
      { status: 401 }
    );
  }

  console.log("[webhook] signature ok", JSON.stringify(describeWebhookBody(rawBody)));

  let payload: unknown;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return NextResponse.json(
      { success: false, error: "Invalid JSON" },
      { status: 400 }
    );
  }

  try {
    await processInstagramWebhook({ payload: payload as Parameters<typeof parseCommentEvents>[0], provider: 'META' });
    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json({ success: false, error: 'Webhook processing failed' }, { status: 500 });
  }
}
