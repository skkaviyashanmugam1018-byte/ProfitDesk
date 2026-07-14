const { Router } = require("express");
const axios  = require("axios");
const crypto = require("crypto");

const router = Router();

const VERIFY_TOKEN     = process.env.WHATSAPP_VERIFY_TOKEN    || "profitdesk_verify_token";
const PHONE_NUMBER_ID  = process.env.WHATSAPP_PHONE_NUMBER_ID;
const ACCESS_TOKEN     = process.env.WHATSAPP_ACCESS_TOKEN;
const CUSTOMER_API     = process.env.CUSTOMER_API_BASE_URL    || "https://prod.thinksoft.in/profitdesk/api/site-engineer";
const FLOW_ID          = process.env.FLOW_ID;
const FLOW_PRIVATE_KEY = process.env.FLOW_PRIVATE_KEY;
const GRAPH_URL        = `https://graph.facebook.com/v20.0/${PHONE_NUMBER_ID}`;
const SESSION_TTL_MS   = 30 * 60 * 1000;
const LOGO_URL         = "https://res.cloudinary.com/dxfphwvnf/image/upload/f_jpg,q_auto/logo_hc2qsg";

function phone10(raw) {
  if (!raw) return "";
  return String(raw).replace(/\D/g, "").slice(-10);
}
function phone91(raw) {
  if (!raw) return "";
  const d = String(raw).replace(/\D/g, "");
  if (d.length === 10) return "91" + d;
  if (d.length === 12 && d.startsWith("91")) return d;
  return d;
}

function decryptFlowRequest(body) {
  const { encrypted_flow_data, encrypted_aes_key, initial_vector } = body;
  const rawKey = (FLOW_PRIVATE_KEY || "").replace(/\\n/g, "\n");
  const pk = crypto.createPrivateKey(rawKey);
  const aesKey = crypto.privateDecrypt(
    { key: pk, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    Buffer.from(encrypted_aes_key, "base64")
  );
  const iv  = Buffer.from(initial_vector, "base64");
  const enc = Buffer.from(encrypted_flow_data, "base64");
  const tag = enc.slice(-16);
  const ct  = enc.slice(0, -16);
  const dc  = crypto.createDecipheriv("aes-128-gcm", aesKey, iv);
  dc.setAuthTag(tag);
  return { decryptedBody: JSON.parse(Buffer.concat([dc.update(ct), dc.final()]).toString()), aesKey, iv };
}

function encryptFlowResponse(obj, aesKey, iv) {
  const flipped = Buffer.from(iv.map(b => ~b & 0xff));
  const c = crypto.createCipheriv("aes-128-gcm", aesKey, flipped);
  const enc = Buffer.concat([c.update(JSON.stringify(obj), "utf8"), c.final()]);
  return Buffer.concat([enc, c.getAuthTag()]).toString("base64");
}

function toDropdownItem(item) {
  return {
    id:    String(item.value ?? item.id ?? ""),
    title: String(item.label || item.title || item.name || "Unknown"),
  };
}
function findName(list, id) {
  if (!list || !id) return String(id || "");
  const item = list.find(i => String(i.value ?? i.id ?? "") === String(id));
  return item ? String(item.label || item.title || item.name || id) : String(id);
}

const sessions     = new Map();
const pendingBills = new Map();

function getSession(from, name) {
  const now = Date.now();
  const ex  = sessions.get(from);
  if (ex && now - ex.createdAt > SESSION_TTL_MS) sessions.delete(from);
  if (!sessions.has(from)) {
    sessions.set(from, { createdAt: now, step: "START", phone: phone10(from), rawPhone: from, name: name || "" });
  }
  const s = sessions.get(from);
  if (name && !s.name) s.name = name;
  return s;
}
function clearSession(from) { sessions.delete(from); }

async function apiPost(endpoint, body) {
  try {
    const res = await axios.post(`${CUSTOMER_API}/${endpoint}`, body, {
      headers: { "Content-Type": "application/json" }, timeout: 15000,
    });
    if (res.data && String(res.data.status).toLowerCase() === "success") return { ok: true, data: res.data.data, message: res.data.message };
    return { ok: false, data: res.data.data, message: res.data.message, code: res.data.code };
  } catch (err) {
    console.error(`[apiPost] ${endpoint} error:`, err.message);
    return { ok: false, message: err.message };
  }
}

async function apiPostWithPhoneFallback(endpoint, baseBody, rawPhone) {
  const p10 = phone10(rawPhone), p91 = phone91(rawPhone);
  let r = await apiPost(endpoint, { ...baseBody, phone: p10 });
  if (r.ok) { console.log(`[apiPost] ${endpoint} matched phone10: ${p10}`); return r.data; }
  r = await apiPost(endpoint, { ...baseBody, phone: p91 });
  if (r.ok) { console.log(`[apiPost] ${endpoint} matched phone91: ${p91}`); return r.data; }
  return null;
}

async function checkUserAccess(rawPhone) {
  const p10 = phone10(rawPhone);
  const p91 = phone91(rawPhone);
  for (const phone of [p10, p91]) {
    try {
      const res = await axios.post(`${CUSTOMER_API}/check`, { phone }, {
        headers: { "Content-Type": "application/json" }, timeout: 15000,
      });
      const d = res.data;
      console.log(`[check] phone=${phone} status=${d.status} msg=${d.message}`);
      if (String(d.status).toLowerCase() === "success") return { allowed: true, message: d.message };
      return { allowed: false, message: d.message || "Access denied. Please contact your admin." };
    } catch (err) {
      console.error(`[check] error for ${phone}:`, err.message);
    }
  }
  return { allowed: false, message: "Unable to verify your account. Please try again later." };
}

async function fetchBaseDropdowns(rawPhone) {
  const companyRes = await apiPostWithPhoneFallback("user-company-list", {}, rawPhone);
  const compArr    = Array.isArray(companyRes) ? companyRes : [];
  const companyId  = compArr[0] ? Number(compArr[0].value ?? compArr[0].id) : 0;
  const [catRes, projRes] = await Promise.all([
    apiPostWithPhoneFallback("category-list",     {},                 rawPhone),
    apiPostWithPhoneFallback("user-project-list", { company_id: companyId }, rawPhone),
  ]);
  const categories = Array.isArray(catRes)  ? catRes.map(toDropdownItem)  : [];
  const projects   = Array.isArray(projRes) ? projRes.map(toDropdownItem) : [];
  if (!categories.length) categories.push({ id: "err", title: "No categories found" });
  if (!projects.length)   projects.push(  { id: "err", title: "No projects found"   });
  return { categories, projects, companyId, catList: catRes, projList: projRes };
}

async function fetchVendorsByCategory(rawPhone, companyId, categoryId) {
  const vendRes   = await apiPostWithPhoneFallback("vendor-list", { company_id: companyId, category_id: categoryId }, rawPhone);
  const vendItems = Array.isArray(vendRes) ? vendRes.filter(v => String(v.value ?? v.id) !== "0").map(toDropdownItem) : [];
  return [{ id: "0", title: "None" }, ...vendItems];
}

async function sendText(to, text) {
  await axios.post(`${GRAPH_URL}/messages`,
    { messaging_product: "whatsapp", to, type: "text", text: { body: text } },
    { headers: { Authorization: `Bearer ${ACCESS_TOKEN}` } }
  );
}

async function sendButtons(to, body, buttons) {
  await axios.post(`${GRAPH_URL}/messages`, {
    messaging_product: "whatsapp", to, type: "interactive",
    interactive: {
      type: "button", body: { text: body },
      action: { buttons: buttons.slice(0, 3).map(b => ({ type: "reply", reply: { id: b.id, title: b.title.slice(0, 20) } })) },
    },
  }, { headers: { Authorization: `Bearer ${ACCESS_TOKEN}` } });
}

async function sendFlow(to, flowToken, rawPhone, bodyText) {
  const { categories, projects } = await fetchBaseDropdowns(rawPhone);
  await axios.post(`${GRAPH_URL}/messages`, {
    messaging_product: "whatsapp", to, type: "interactive",
    interactive: {
      type: "flow", body: { text: bodyText },
      action: {
        name: "flow",
        parameters: {
          flow_message_version: "3", flow_token: flowToken,
          flow_id: FLOW_ID, flow_cta: "Open Bill Form", flow_action: "navigate",
          flow_action_payload: { screen: "BILL_FORM", data: { categories, projects, error_message: "" } },
        },
      },
    },
  }, { headers: { Authorization: `Bearer ${ACCESS_TOKEN}` } });
}

async function stepWelcome(from, session) {
  const name = session.name || "there";
  const access = await checkUserAccess(from);
  if (!access.allowed) {
    console.log(`[stepWelcome] access denied: ${access.message}`);
    await sendText(from, `❌ ${access.message}`);
    clearSession(from); return;
  }
  console.log(`[stepWelcome] access granted for ${name}`);
  try {
    await axios.post(`${GRAPH_URL}/messages`, {
      messaging_product: "whatsapp", to: from, type: "image",
      image: { link: LOGO_URL, caption: `Hi ${name}, Welcome to ProfitDesk!\n\nWE TRACK YOUR SITE, YOU TRACK YOUR GROWTH.` },
    }, { headers: { Authorization: `Bearer ${ACCESS_TOKEN}` } });
    console.log("[stepWelcome] logo sent ✅");
  } catch (e) { console.warn("[stepWelcome] logo failed:", e.message); }
  try {
    await sendFlow(from, phone91(from), from, "Click below to create a new bill.");
    session.step = "FLOW_SENT";
  } catch (e) {
    console.error("[stepWelcome] flow failed:", e.message);
    await sendText(from, "Sorry, something went wrong. Please try again.");
    clearSession(from);
  }
}

async function handleMessage(from, message, contactName) {
  const session = getSession(from, contactName);

  if (message.type === "interactive") {
    const iType = message.interactive.type;
    const selectedId = iType === "button_reply" ? message.interactive.button_reply.id
                     : iType === "list_reply"   ? message.interactive.list_reply.id : "";

    if (selectedId === "submit_another_bill") {
      clearSession(from); pendingBills.delete(from);
      const access = await checkUserAccess(from);
      if (!access.allowed) { await sendText(from, `❌ ${access.message}`); return; }
      const ns = getSession(from, contactName); ns.step = "FLOW_SENT";
      await sendFlow(from, phone91(from), from, "Tap to submit another bill.");
      return;
    }

    if (selectedId === "confirm_submit") {
      const pending = pendingBills.get(from);
      if (!pending) { await sendText(from, "Session expired. Send hi to restart."); return; }
      pendingBills.delete(from);
      session.step = "SUBMITTING";
      const now  = new Date();
      const date = now.toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" });
      const time = now.toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit", hour12: true });
      const submitResult = await apiPostWithPhoneFallback("bill-submit", {
        company_id:  pending.companyId,
        date, on_time: time,
        category_id: pending.category,
        project_id:  pending.project,
        supplier_id: (!pending.vendor || pending.vendor === "0") ? 0 : Number(pending.vendor),
        amount:      Number(pending.amount),
        remarks:     pending.remarks || "",
        item:        JSON.stringify(pending.allFiles),
      }, from);

      if (submitResult) {
        const bill     = typeof submitResult === "object" ? submitResult : {};
        const billNo   = bill.ref_bill_no || "—";
        const catName  = bill.category || pending.catName;
        const projName = bill.project  || pending.projName;
        const vendName = bill.vendor   || pending.vendName;
        setImmediate(async () => {
          try {
            const Bill = require("../models/Bill");
            await Bill.create({ source: "whatsapp_flow", category: catName, amount: Number(pending.amount), vendor: vendName, remarks: pending.remarks || "", status: "Not Started", attachments: [] });
          } catch (e) { console.warn("[MongoDB] save skipped:", e.message); }
        });
        clearSession(from);
        await sendButtons(from,
          `✅ Bill Submitted Successfully!\n\n` +
          `Bill No: ${billNo}\n` +
          `Category: ${catName}\n` +
          `Project:  ${projName}\n` +
          `Vendor:   ${vendName}\n` +
          `Amount:   Rs.${Number(pending.amount).toLocaleString("en-IN")}\n` +
          `Files:    ${pending.allFiles.length} file(s)\n\n` +
          `Tap below to submit another bill.`,
          [{ id: "submit_another_bill", title: "Submit Another Bill" }]
        );
      } else {
        await sendText(from, "❌ Submission failed. Send hi to restart.");
        clearSession(from);
      }
      return;
    }

    if (selectedId === "cancel_submit") {
      pendingBills.delete(from); clearSession(from);
      await sendText(from, "Bill cancelled. Send hi to start again.");
      return;
    }
    return;
  }

  const text  = String(message.text?.body || "").trim();
  const lower = text.toLowerCase();
  if (lower === "cancel") { clearSession(from); pendingBills.delete(from); await sendText(from, "Cancelled. Send hi to start again."); return; }

  switch (session.step) {
    case "START":
      if (["hi","hello","hey","hii","hai","helo"].includes(lower)) await stepWelcome(from, session);
      else await sendText(from, "Send hi to get started with ProfitDesk.");
      break;
    case "FLOW_SENT":
      if (["hi","hello"].includes(lower)) { clearSession(from); await stepWelcome(from, getSession(from, contactName)); }
      else await sendText(from, "Please fill the bill form above. Type cancel to restart.");
      break;
    default:
      if (["hi","hello"].includes(lower)) { clearSession(from); await stepWelcome(from, getSession(from, contactName)); }
      else await sendText(from, "Send hi to get started.");
  }
}

router.post("/flow", async (req, res) => {
  console.log(`\n📋 Flow webhook | keys=${Object.keys(req.body).join(",")}`);
  try {
    let decryptedBody, aesKey, iv;
    try {
      const r = decryptFlowRequest(req.body);
      decryptedBody = r.decryptedBody; aesKey = r.aesKey; iv = r.iv;
    } catch (e) { console.error("[Flow] Decrypt error:", e.message); return res.status(421).send("Decryption failed"); }

    const { screen, data = {}, flow_token, action } = decryptedBody;
    const rawPhone = flow_token || "";
    console.log(`📋 screen=${screen || "INIT"} | action=${action} | phone=${rawPhone}`);

    const reply = obj => res.status(200).send(encryptFlowResponse(obj, aesKey, iv));

    if (action === "ping") return reply({ data: { status: "active" } });

    // INIT
    if (action === "INIT" || !screen || screen === "INIT") {
      const { categories, projects } = await fetchBaseDropdowns(rawPhone);
      return reply({ screen: "BILL_FORM", data: { categories, projects, error_message: "" } });
    }

    // BILL_FORM → ADD_FILES
    if (screen === "BILL_FORM") {
      const { category, project, amount, remarks } = data;
      if (!category || !project || !amount) return reply({ screen: "BILL_FORM", data: { error_message: "Category, Project and Amount are required." } });
      if (isNaN(Number(amount)) || Number(amount) <= 0) return reply({ screen: "BILL_FORM", data: { error_message: "Please enter a valid amount." } });
      return reply({
        screen: "ADD_FILES",
        data: { error_message: "", category, project, amount: String(amount), remarks: remarks || "" },
      });
    }

    // ADD_FILES → SELECT_VENDOR (fetch vendors by category)
    if (screen === "ADD_FILES") {
      const { category, project, amount, remarks, photos, documents } = data;
      const allFiles = [...(Array.isArray(photos) ? photos : []), ...(Array.isArray(documents) ? documents : [])];

      // Validate: at least one file required
      if (allFiles.length === 0) {
        return reply({ screen: "ADD_FILES", data: { error_message: "Please upload at least one photo or document.", category, project, amount, remarks: remarks || "" } });
      }

      const companyRes = await apiPostWithPhoneFallback("user-company-list", {}, rawPhone);
      const compArr    = Array.isArray(companyRes) ? companyRes : [];
      const companyId  = compArr[0] ? Number(compArr[0].value ?? compArr[0].id) : 0;
      const vendors    = await fetchVendorsByCategory(rawPhone, companyId, Number(category));

      console.log(`[ADD_FILES] files=${allFiles.length} vendors=${vendors.length}`);
      return reply({
        screen: "SELECT_VENDOR",
        data: { error_message: "", vendors, category, project, amount, remarks: remarks || "", photos: Array.isArray(photos) ? photos : [], documents: Array.isArray(documents) ? documents : [] },
      });
    }

    // SELECT_VENDOR → Summary (WhatsApp chat)
    if (screen === "SELECT_VENDOR") {
      const { vendor, category, project, amount, remarks, photos, documents } = data;
      const allFiles = [...(Array.isArray(photos) ? photos : []), ...(Array.isArray(documents) ? documents : [])];

      const { catList, projList, companyId } = await fetchBaseDropdowns(rawPhone);
      const vendList = await fetchVendorsByCategory(rawPhone, companyId, Number(category));

      const catName  = findName(catList,  category);
      const projName = findName(projList, project);
      const vendName = (!vendor || vendor === "0") ? "None" : findName(vendList, vendor);

      console.log(`[SELECT_VENDOR] cat=${catName} proj=${projName} vendor=${vendName} files=${allFiles.length}`);

      const userPhone = phone91(rawPhone);
      pendingBills.set(userPhone, { category, project, vendor, amount, remarks, allFiles, catName, projName, vendName, companyId });
      const session = getSession(userPhone);
      session.step  = "CONFIRMING";

      try {
        await sendButtons(userPhone,
          `📋 Bill Summary\n\n` +
          `Category: ${catName}\n` +
          `Project:  ${projName}\n` +
          `Vendor:   ${vendName}\n` +
          `Amount:   Rs.${Number(amount).toLocaleString("en-IN")}\n` +
          `Remarks:  ${remarks || "-"}\n` +
          `Files:    ${allFiles.length} file(s)\n\n` +
          `Please confirm to submit.`,
          [
            { id: "confirm_submit", title: "✅ Confirm & Submit" },
            { id: "cancel_submit",  title: "❌ Cancel" },
          ]
        );
      } catch (e) { console.warn("[Flow] Summary failed:", e.message); }

      return reply({ screen: "SUCCESS", data: {} });
    }

    if (screen === "SUCCESS") return reply({ data: { status: "ok" } });

    return res.status(400).send("Unknown screen");
  } catch (err) {
    console.error("[Flow] Unhandled error:", err?.response?.data || err.message);
    return res.status(500).send("Server error");
  }
});

router.get("/whatsapp", (req, res) => {
  const { "hub.mode": mode, "hub.verify_token": token, "hub.challenge": challenge } = req.query;
  if (mode === "subscribe" && token === VERIFY_TOKEN) res.status(200).send(challenge);
  else res.status(403).send("Forbidden");
});

router.post("/whatsapp", (req, res) => {
  res.sendStatus(200);
  const body = req.body;
  if (body.object !== "whatsapp_business_account") return;
  (async () => {
    for (const entry of body.entry || []) {
      for (const change of entry.changes || []) {
        const messages = change.value?.messages;
        if (!messages?.length) continue;
        const contactName = change.value?.contacts?.[0]?.profile?.name || "";
        for (const msg of messages) {
          try { await handleMessage(msg.from, msg, contactName); }
          catch (e) { console.error("Handler error:", e); }
        }
      }
    }
  })().catch(console.error);
});

module.exports = router;
        
