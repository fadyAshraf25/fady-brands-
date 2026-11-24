export const attachmentLimit = 10 * 1024 * 1024;
const envelopeLimit = attachmentLimit + 128 * 1024;
const problem = (status, code) => Object.assign(new Error(code), {status});

async function boundedBody(req, limit) {
  if (Number(req.headers.get("content-length")) > limit) throw problem(413, "size");
  const reader = req.body?.getReader();
  if (!reader) throw problem(400, "fields");
  const chunks = [];
  let size = 0;
  for (;;) {
    const {done, value} = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw problem(413, "size");
    }
    chunks.push(value);
  }
  return new Response(new Blob(chunks), {headers: {"content-type": req.headers.get("content-type") || ""}});
}

export async function parseInquiry(req) {
  const type = req.headers.get("content-type") || "";
  let data;
  let files = [];
  if (type.startsWith("multipart/form-data")) {
    const body = await boundedBody(req, envelopeLimit);
    const form = await body.formData().catch(() => { throw problem(400, "fields"); });
    files = form.getAll("attachments").filter(file => typeof file !== "string" && file.name);
    data = Object.fromEntries(form);
  } else if (type.startsWith("application/json")) {
    const body = await boundedBody(req, 55000);
    data = await body.json().catch(() => null);
  } else throw problem(415, "fields");

  const get = (key, max, required = false) => {
    const v = data?.[key] ?? "";
    if (typeof v !== "string" || v.length > max || (required && !v.trim())) throw problem(400, "fields");
    return v.trim();
  };
  const id = get("id", 36, true);
  const preferred = get("preferred", 10) || "email";
  const email = get("email", 254, preferred === "email");
  const phone = get("phone", 40, preferred === "whatsapp");
  if (!/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i.test(id) ||
      !["email", "whatsapp"].includes(preferred) || get("website", 0) ||
      (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) ||
      (phone && (!/^[+\d\s().-]+$/.test(phone) || !/^\d{7,15}$/.test(phone.replace(/\D/g, ""))))) throw problem(400, "fields");
  if (files.reduce((n, f) => n + f.size, 0) > attachmentLimit) throw problem(413, "size");
  for (const file of files) {
    if (!file.size || !/\.pdf$/i.test(file.name) || file.name.length > 255 ||
        await file.slice(0,5).text() !== "%PDF-") throw problem(400, "file");
  }
  return {id, preferred, email, phone, name:get("name",140,true), service:get("service",220,true),
    budget:get("budget",180), brief:get("brief",6000,true), files};
}

export const attachmentDisposition = name => "attachment; filename=\"project-file.pdf\"; filename*=UTF-8''" +
  encodeURIComponent(name).replace(/['()*]/g, c => "%" + c.charCodeAt(0).toString(16));

