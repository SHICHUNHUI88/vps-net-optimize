export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 健康检查
    if (url.pathname === "/") {
      return new Response("ok", { status: 200 });
    }

    // Telegram Webhook 入口
    if (url.pathname === "/telegram") {
      if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

      const update = await request.json().catch(() => null);
      if (!update) return new Response("Bad Request", { status: 400 });

      const msg = update.message || update.edited_message;
      if (!msg || !msg.chat || !msg.text) return new Response("ok", { status: 200 });

      const chatId = msg.chat.id;
      const text = msg.text.trim();

      // 简单命令
      if (text === "/start") {
        await tgSend(env, chatId, "我在。直接发消息，我会像AI一样跟你聊。");
        return new Response("ok", { status: 200 });
      }

      // 调 OpenAI
      const reply = await callOpenAI(env, text).catch((e) => `出错了：${e?.message || e}`);
      await tgSend(env, chatId, reply);

      return new Response("ok", { status: 200 });
    }

    return new Response("Not Found", { status: 404 });
  },
};

async function tgSend(env, chatId, text) {
  const api = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`;
  const res = await fetch(api, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text,
      disable_web_page_preview: true,
    }),
  });

  // 不抛异常也行，但建议记录
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    console.log("tgSend failed:", res.status, t);
  }
}

async function callOpenAI(env, userText) {
  const model = env.OPENAI_MODEL || "gpt-4.1-mini";

  // 这里用 OpenAI REST API：Authorization Bearer <key>
  // 具体鉴权方式见 OpenAI API 文档
  const res = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model,
      input: [
        { role: "system", content: env.SYSTEM_PROMPT || "你是一个中文聊天助手。" },
        { role: "user", content: userText },
      ],
    }),
  });

  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`OpenAI API ${res.status}: ${t}`);
  }

  const data = await res.json();

  // responses API 的输出字段较灵活，这里做一个稳妥抽取
  const text = data.output_text;
  if (typeof text === "string" && text.trim()) return text.trim();

  // 兜底：尝试从 output[] 里拼
  const out = Array.isArray(data.output) ? data.output : [];
  for (const item of out) {
    const c = item?.content;
    if (Array.isArray(c)) {
      const t2 = c.map(x => x?.text).filter(Boolean).join("");
      if (t2.trim()) return t2.trim();
    }
  }
  return "（我收到了，但没生成出可读文本）";
}