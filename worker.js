// worker.js
// Cloudflare Workers + Telegram Bot Webhook + Cloudflare Workers AI (free-tier)
// Required Secret: TELEGRAM_BOT_TOKEN
// Optional Secret: SYSTEM_PROMPT

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/") {
      return new Response("ok", { status: 200 });
    }

    // Telegram webhook endpoint
    if (url.pathname === "/telegram") {
      if (request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
      }

      const update = await request.json().catch(() => null);
      if (!update) return new Response("Bad Request", { status: 400 });

      const msg = update.message || update.edited_message;
      if (!msg || !msg.chat) return new Response("ok", { status: 200 });

      const chatId = msg.chat.id;
      const text = (msg.text || "").trim();

      // Ignore non-text messages for now (stickers, photos, etc.)
      if (!text) return new Response("ok", { status: 200 });

      // Commands
      if (text === "/start") {
        await tgSend(env, chatId, "我在。直接发消息，我会像AI一样跟你聊（免费模型）。\n\n命令：/help /ping /reset");
        return new Response("ok", { status: 200 });
      }

      if (text === "/help") {
        await tgSend(
          env,
          chatId,
          [
            "可用命令：",
            "/ping  测试是否在线",
            "/reset 清空（当前版本不保存上下文，这个只是占位）",
            "",
            "直接发文字，我会回复。",
          ].join("\n")
        );
        return new Response("ok", { status: 200 });
      }

      if (text === "/ping") {
        await tgSend(env, chatId, "pong ✅ 我在线");
        return new Response("ok", { status: 200 });
      }

      if (text === "/reset") {
        await tgSend(env, chatId, "已重置 ✅（当前版本是单轮对话，不保存历史）");
        return new Response("ok", { status: 200 });
      }

      // Call Workers AI (free model)
      let reply = "";
      try {
        reply = await callWorkersAI(env, text);
      } catch (e) {
        reply = `出错了：${e?.message || e}`;
      }

      // Send reply
      await tgSend(env, chatId, reply || "（我收到了，但没生成出可读文本）");

      return new Response("ok", { status: 200 });
    }

    return new Response("Not Found", { status: 404 });
  },
};

// -------------------- Telegram helpers --------------------

async function tgSend(env, chatId, text) {
  const token = env.TELEGRAM_BOT_TOKEN;
  if (!token) {
    console.log("Missing TELEGRAM_BOT_TOKEN secret");
    return;
  }

  // Telegram message limit is ~4096 chars; keep it safe
  const safeText = String(text || "").slice(0, 3800);

  const api = `https://api.telegram.org/bot${token}/sendMessage`;
  const res = await fetch(api, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text: safeText,
      disable_web_page_preview: true,
    }),
  });

  if (!res.ok) {
    const t = await res.text().catch(() => "");
    console.log("tgSend failed:", res.status, t);
  }
}

// -------------------- Workers AI --------------------

async function callWorkersAI(env, userText) {
  if (!env.AI) {
    throw new Error('Workers AI 未绑定：请在 wrangler.toml 添加 [ai]\\nbinding="AI" 并重新部署');
  }

  // Fast, good enough for chat. You can switch to non-fast if you prefer.
  const model = "@cf/meta/llama-3.1-8b-instruct-fast";

  const system =
    env.SYSTEM_PROMPT ||
    "你是一个中文聊天助手。回答要简洁、直接、实用。不要胡编；不确定就说明不确定。";

  // Simple single-turn prompt (no memory yet)
  const prompt = `${system}\n\n用户：${userText}\n助手：`;

  const result = await env.AI.run(model, {
    prompt,
    max_tokens: 512,
  });

  // Workers AI commonly returns { response: "..." }
  const text = (result && result.response) ? String(result.response) : "";

  return text.trim();
}