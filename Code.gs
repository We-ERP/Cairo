/**
 * ==========================================================================
 *  منظومة إدارة الانتخابات - Backend (Google Apps Script)
 *  ---------------------------------------------------------------------
 *  ملاحظة مهمة: كل المنطق الأصلي لحساب الماتريكس، فتح اللجان، وإدخال
 *  الأرقام لم يتم تغييره إطلاقًا. الإضافات هنا كلها طبقة حماية/أداء فوق
 *  نفس المنطق: تسجيل دخول بجلسة (Session) حقيقية، تشفير كلمات المرور،
 *  صلاحيات تفصيلية لكل مستخدم، وأقفال (Lock) لمنع تعارض الكتابة.
 * ==========================================================================
 */

// ==================== الإعدادات العامة ====================
const CONFIG = {
  // مهم جدًا: غيّر هذا المفتاح لأي قيمة عشوائية طويلة خاصة بمشروعك قبل النشر.
  SESSION_SECRET: "REPLACE_THIS_WITH_A_LONG_RANDOM_SECRET_STRING",
  SESSION_TTL_MINUTES: 480, // مدة صلاحية الجلسة (8 ساعات)
  // الشيتات المسموح عرضها/تنزيلها من شاشة "مراجعة الشيتات"
  ALLOWED_MIRROR_SHEETS: ["Data", "Election_July", "Codes", "الاجمالي", "صلاحيات المستخدمين"],
  // الأعمدة الحساسة التي يجب إخفاؤها دائمًا عند عرض/تصدير شيت الصلاحيات
  SENSITIVE_COLUMN_PATTERNS: ["كلمة المرور", "PASSWORD", "PASS", "الملح", "SALT"]
};

// خريطة: كل أكشن يحتاج أي صلاحية (Capability) لتنفيذه. null = يكفي وجود جلسة صالحة فقط.
const ACTION_CAPABILITY = {
  getCenters: "enterData",
  saveData: "enterData",
  getCommitteesForPanel: "enterData",
  saveCommitteeOpen: "enterData",
  getSheetDataMirror: "mirrors",
  getFinalMatrixData: "totals",
  getAdminDashboard: "dashboard",
  getUserPermissions: "manageUsers",
  saveUserPermission: "manageUsers",
  downloadAdminReport: "dashboard",
  downloadSheetReport: "mirrors",
  getActivityLog: "activityLog",
  changePassword: null
};

// الأكشنز التي لا تحتاج جلسة أصلًا (تسجيل الدخول نفسه)
const PUBLIC_ACTIONS = ["checkLogin", "validateSession"];

// ==================== نقطة الدخول doPost / doGet ====================
function doPost(e) {
  try {
    const params = JSON.parse(e.postData.contents);
    const action = params.action;

    if (!action) {
      return jsonOutput({ error: "Action not found" });
    }

    let auth = null;

    // التحقق من الجلسة والصلاحية قبل تنفيذ أي أكشن محمي
    if (PUBLIC_ACTIONS.indexOf(action) === -1) {
      const requiredCapability = ACTION_CAPABILITY.hasOwnProperty(action) ? ACTION_CAPABILITY[action] : undefined;
      if (requiredCapability === undefined) {
        return jsonOutput({ error: "Action not found" });
      }
      auth = requireSession(params.token, requiredCapability);
      if (!auth.ok) {
        return jsonOutput({ authError: true, msg: auth.error });
      }

      // حماية إضافية: أي مستخدم غير أدمن لا يقدر يتصرف إلا في قسمه المسموح به،
      // حتى لو حاول من الواجهة (Console) إرسال قسم مختلف.
      if (auth.role !== "ADMIN" && params.hasOwnProperty("section")) {
        params.section = auth.section;
      }
    }

    let result;
    if (action === "checkLogin") {
      result = checkLogin(params.username, params.password);
    } else if (action === "validateSession") {
      result = validateSession(params.token);
    } else if (action === "changePassword") {
      result = changePassword(auth.username, params.oldPassword, params.newPassword);
    } else if (action === "getCenters") {
      result = getCenters();
    } else if (action === "saveData") {
      result = saveData(params.number, params.section, params.center, params.committee, auth.username);
    } else if (action === "getCommitteesForPanel") {
      result = getCommitteesForPanel(params.section);
    } else if (action === "saveCommitteeOpen") {
      result = saveCommitteeOpen(auth.username, params.committeeNumber, params.value);
    } else if (action === "getSheetDataMirror") {
      result = getSheetDataMirror(params.sheetName, auth.username);
    } else if (action === "getFinalMatrixData") {
      result = getFinalMatrixData(params.section);
    } else if (action === "getAdminDashboard") {
      result = getAdminDashboard();
    } else if (action === "getUserPermissions") {
      result = getUserPermissions();
    } else if (action === "saveUserPermission") {
      result = saveUserPermission(params.username, params.password, params.section, params.role, params.capabilities, auth.username);
    } else if (action === "downloadAdminReport") {
      result = downloadAdminReport(auth.username);
    } else if (action === "downloadSheetReport") {
      result = downloadSheetReport(params.sheetName, auth.username);
    } else if (action === "getActivityLog") {
      result = getActivityLog(params.limit);
    } else {
      result = { error: "Action not found" };
    }

    return jsonOutput(result);

  } catch (error) {
    return jsonOutput({ error: error.toString() });
  }
}

function doGet() {
  return ContentService.createTextOutput("API is running... Please use POST requests from the Frontend.")
    .setMimeType(ContentService.MimeType.TEXT);
}

function jsonOutput(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

// ==================== الأمان: الجلسات (Sessions) ====================

function base64UrlFromString(str) {
  return Utilities.base64EncodeWebSafe(Utilities.newBlob(str).getBytes());
}

function stringFromBase64Url(b64) {
  return Utilities.newBlob(Utilities.base64DecodeWebSafe(b64)).getDataAsString();
}

function signPayload(payloadB64) {
  const signatureBytes = Utilities.computeHmacSha256Signature(payloadB64, CONFIG.SESSION_SECRET);
  return Utilities.base64EncodeWebSafe(signatureBytes);
}

function createSessionToken(username) {
  const payload = {
    u: username,
    exp: Date.now() + CONFIG.SESSION_TTL_MINUTES * 60 * 1000
  };
  const payloadB64 = base64UrlFromString(JSON.stringify(payload));
  const signature = signPayload(payloadB64);
  return payloadB64 + "." + signature;
}

function verifySessionToken(token) {
  if (!token || token.indexOf(".") === -1) return null;
  const parts = token.split(".");
  const payloadB64 = parts[0];
  const signature = parts[1];
  const expectedSignature = signPayload(payloadB64);
  if (signature !== expectedSignature) return null;

  try {
    const payload = JSON.parse(stringFromBase64Url(payloadB64));
    if (!payload.u || !payload.exp || payload.exp < Date.now()) return null;
    return { username: payload.u };
  } catch (err) {
    return null;
  }
}

// يتحقق من الجلسة، ويعيد تحميل صلاحيات المستخدم "حية" من الشيت في كل مرة
// (بمعنى لو الأدمن سحب صلاحية من مستخدم، هتتفعل فورًا من غير ما يحتاج يعمل تسجيل خروج/دخول)
function requireSession(token, requiredCapability) {
  const session = verifySessionToken(token);
  if (!session) {
    return { ok: false, error: "انتهت صلاحية الجلسة، برجاء تسجيل الدخول مرة أخرى" };
  }

  const userRow = getUserPermissionRow(session.username);
  if (!userRow) {
    return { ok: false, error: "المستخدم غير موجود أو تم حذفه" };
  }

  if (requiredCapability && !userRow.capabilities[requiredCapability]) {
    return { ok: false, error: "ليس لديك صلاحية لتنفيذ هذا الإجراء" };
  }

  return {
    ok: true,
    username: session.username,
    role: userRow.role,
    section: userRow.section,
    capabilities: userRow.capabilities
  };
}

// ==================== الأمان: كلمات المرور ====================

function generateSalt() {
  return Utilities.getUuid();
}

function hashPassword(password, salt) {
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt + "|" + password);
  return Utilities.base64EncodeWebSafe(digest);
}

// ==================== الصلاحيات التفصيلية (Capabilities) ====================

const CAPABILITY_KEYS = ["enterData", "dashboard", "manageUsers", "mirrors", "activityLog", "totals"];

function defaultCapabilitiesForRole(role) {
  const isAdmin = normalize(role) === "ADMIN";
  const caps = {};
  CAPABILITY_KEYS.forEach(function (key) {
    caps[key] = isAdmin ? true : (key === "enterData");
  });
  return caps;
}

function parseCapabilities(raw, role) {
  if (!raw) return defaultCapabilitiesForRole(role);
  try {
    const parsed = JSON.parse(raw);
    const caps = defaultCapabilitiesForRole(role);
    CAPABILITY_KEYS.forEach(function (key) {
      if (parsed.hasOwnProperty(key)) caps[key] = !!parsed[key];
    });
    return caps;
  } catch (err) {
    return defaultCapabilitiesForRole(role);
  }
}

// ==================== الدوال الأصلية المساعدة (Logic - بدون تغيير) ====================

function normalize(value) {
  return (value || "").toString().trim().toUpperCase();
}

function findColumnIndex(headers, patterns) {
  for (let i = 0; i < headers.length; i++) {
    const header = normalize(headers[i] || "");
    if (patterns.some(pattern => header.includes(normalize(pattern)))) {
      return i;
    }
  }
  return -1;
}

function findAllColumnIndices(headers, patterns) {
  const indices = [];
  for (let i = 0; i < headers.length; i++) {
    const header = normalize(headers[i] || "");
    if (patterns.some(pattern => header.includes(normalize(pattern)))) {
      indices.push(i);
    }
  }
  return indices;
}

function findSheetByName(ss, patterns) {
  const normalizedPatterns = patterns.map(normalize);
  const sheets = ss.getSheets();

  for (let i = 0; i < sheets.length; i++) {
    const name = normalize(sheets[i].getName());
    if (normalizedPatterns.includes(name)) {
      return sheets[i];
    }
  }

  for (let i = 0; i < sheets.length; i++) {
    const name = normalize(sheets[i].getName());
    if (normalizedPatterns.some(pattern => name.includes(pattern))) {
      return sheets[i];
    }
  }
  return null;
}

function logAction(username, section, action, details) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = findSheetByName(ss, ["سجل الحركات", "Activity Log", "Logs"]);
  if (!sheet) {
    sheet = ss.insertSheet("سجل الحركات");
    sheet.appendRow(["Timestamp", "Username", "Section", "Action", "Details"]);
  }
  const now = new Date();
  sheet.appendRow([now, username || "", section || "", action || "", details || ""]);
}

function getActivityLog(limit) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = findSheetByName(ss, ["سجل الحركات", "Activity Log", "Logs"]);
  if (!sheet) return [];

  const data = sheet.getDataRange().getDisplayValues();
  if (!data || data.length < 2) return [];

  const rows = data.slice(1).map(row => ({
    timestamp: row[0],
    username: row[1],
    section: row[2],
    action: row[3],
    details: row[4]
  }));

  return rows.reverse().slice(0, limit || 100);
}

// ==================== شيت الصلاحيات: قراءة/تحضير الأعمدة ====================

function getPermissionsSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  return findSheetByName(ss, ["صلاحيات المستخدمين", "User Permissions", "Permissions"]);
}

// يضيف عمودي "الملح" و"الصلاحيات التفصيلية" تلقائيًا لو مش موجودين، من غير ما يمس أي عمود موجود.
function ensurePermissionColumns(sheet) {
  const lastCol = sheet.getLastColumn();
  const headers = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
  const hasSalt = findColumnIndex(headers, ["الملح", "SALT"]) !== -1;
  const hasCaps = findColumnIndex(headers, ["الصلاحيات التفصيلية", "CAPABILITIES"]) !== -1;

  let nextCol = lastCol;
  if (!hasSalt) {
    nextCol++;
    sheet.getRange(1, nextCol).setValue("الملح");
  }
  if (!hasCaps) {
    nextCol++;
    sheet.getRange(1, nextCol).setValue("الصلاحيات التفصيلية");
  }
}

function getUserPermissionRow(username) {
  const sheet = getPermissionsSheet();
  if (!sheet) return null;
  ensurePermissionColumns(sheet);

  const data = sheet.getDataRange().getValues();
  if (!data || data.length < 2) return null;

  const headers = data[0];
  const userIdxs = findAllColumnIndices(headers, ["اسم المستخدم", "USER"]);
  const passIdxs = findAllColumnIndices(headers, ["كلمة المرور", "PASSWORD", "PASS"]);
  const saltIdx = findColumnIndex(headers, ["الملح", "SALT"]);
  const sectionIdx = findColumnIndex(headers, ["القسم", "SECTION"]);
  const roleIdx = findColumnIndex(headers, ["الصلاحية", "ROLE"]);
  const capsIdx = findColumnIndex(headers, ["الصلاحيات التفصيلية", "CAPABILITIES"]);

  const inputUser = normalize(username);
  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    for (let u = 0; u < userIdxs.length; u++) {
      const ui = userIdxs[u];
      if (ui !== -1 && normalize(row[ui]) === inputUser) {
        const role = roleIdx !== -1 ? normalize(row[roleIdx]) : "USER";
        return {
          rowNumber: i + 1,
          section: sectionIdx !== -1 ? normalize(row[sectionIdx]) : "",
          role: role,
          capabilities: parseCapabilities(capsIdx !== -1 ? row[capsIdx] : "", role),
          passwordValue: passIdxs.length > 0 ? row[passIdxs[0]] : "",
          passIdx: passIdxs.length > 0 ? passIdxs[0] : -1,
          saltValue: saltIdx !== -1 ? row[saltIdx] : "",
          saltIdx: saltIdx
        };
      }
    }
  }
  return null;
}

// ==================== تسجيل الدخول ====================

function checkLogin(username, password) {
  const sheet = getPermissionsSheet();
  if (!sheet) return { success: false };
  ensurePermissionColumns(sheet);

  const userRow = getUserPermissionRow(username);
  if (!userRow) {
    logAction(username, "", "login-failed", "فشل تسجيل الدخول: اسم المستخدم أو كلمة المرور غير صحيحة");
    return { success: false };
  }

  let passwordMatches = false;

  if (userRow.saltValue) {
    // حساب مُشفّر بالفعل
    passwordMatches = hashPassword(password, userRow.saltValue) === userRow.passwordValue;
  } else {
    // حساب قديم بكلمة مرور نص صريح -> نتحقق ثم نرقّيه تلقائيًا لتشفير
    passwordMatches = normalize(password) === normalize(userRow.passwordValue);
    if (passwordMatches && userRow.passIdx !== -1 && userRow.saltIdx !== -1) {
      const newSalt = generateSalt();
      const newHash = hashPassword(password, newSalt);
      sheet.getRange(userRow.rowNumber, userRow.passIdx + 1).setValue(newHash);
      sheet.getRange(userRow.rowNumber, userRow.saltIdx + 1).setValue(newSalt);
    }
  }

  if (!passwordMatches) {
    logAction(username, userRow.section, "login-failed", "فشل تسجيل الدخول: اسم المستخدم أو كلمة المرور غير صحيحة");
    return { success: false };
  }

  // تحديث آخر تسجيل دخول (نفس المنطق الأصلي)
  const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
  const loginTimeIdx = findColumnIndex(headers, ["آخر تسجيل دخول", "LAST LOGIN", "LOGIN"]);
  if (loginTimeIdx !== -1) {
    const today = new Date();
    const todayDate = Utilities.formatDate(today, Session.getScriptTimeZone(), "yyyy-MM-dd");
    const currentValue = sheet.getRange(userRow.rowNumber, loginTimeIdx + 1).getValue();
    if (!currentValue || Utilities.formatDate(new Date(currentValue), Session.getScriptTimeZone(), "yyyy-MM-dd") !== todayDate) {
      sheet.getRange(userRow.rowNumber, loginTimeIdx + 1).setValue(today);
    }
  }

  logAction(username, userRow.section, "login-success", "تم تسجيل الدخول بنجاح");

  const token = createSessionToken(normalize(username));
  return {
    success: true,
    section: userRow.section,
    role: userRow.role,
    capabilities: userRow.capabilities,
    token: token
  };
}

// يُستخدم لاستعادة الجلسة تلقائيًا عند تحديث الصفحة
function validateSession(token) {
  const auth = requireSession(token, null);
  if (!auth.ok) return { success: false };
  return {
    success: true,
    username: auth.username,
    section: auth.section,
    role: auth.role,
    capabilities: auth.capabilities,
    token: token
  };
}

// تغيير كلمة المرور الذاتي (أي مستخدم يقدر يغيّر كلمة مروره هو فقط)
function changePassword(username, oldPassword, newPassword) {
  if (!newPassword || newPassword.toString().trim().length < 4) {
    return { success: false, msg: "كلمة المرور الجديدة يجب ألا تقل عن 4 خانات" };
  }

  const lock = LockService.getScriptLock();
  lock.waitLock(15000);
  try {
    const sheet = getPermissionsSheet();
    if (!sheet) return { success: false, msg: "تعذر الوصول لشيت الصلاحيات" };
    ensurePermissionColumns(sheet);

    const userRow = getUserPermissionRow(username);
    if (!userRow) return { success: false, msg: "المستخدم غير موجود" };

    let oldMatches;
    if (userRow.saltValue) {
      oldMatches = hashPassword(oldPassword, userRow.saltValue) === userRow.passwordValue;
    } else {
      oldMatches = normalize(oldPassword) === normalize(userRow.passwordValue);
    }

    if (!oldMatches) {
      return { success: false, msg: "كلمة المرور الحالية غير صحيحة" };
    }

    const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
    const saltIdx = findColumnIndex(headers, ["الملح", "SALT"]);
    const passIdx = findColumnIndex(headers, ["كلمة المرور", "PASSWORD", "PASS"]);

    const newSalt = generateSalt();
    const newHash = hashPassword(newPassword, newSalt);
    sheet.getRange(userRow.rowNumber, passIdx + 1).setValue(newHash);
    sheet.getRange(userRow.rowNumber, saltIdx + 1).setValue(newSalt);

    logAction(username, userRow.section, "change-password", "قام المستخدم بتغيير كلمة المرور الخاصة به");
    return { success: true, msg: "تم تغيير كلمة المرور بنجاح" };
  } finally {
    lock.releaseLock();
  }
}

// ==================== منطق العمل الأصلي (بدون أي تغيير في الحسابات) ====================

function getCenters() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName("Election_July");
  const data = sheet.getDataRange().getValues();
  let result = [];

  for (let i = 1; i < data.length; i++) {
    result.push({
      section: normalize(data[i][0]),
      center: normalize(data[i][1]),
      committee: normalize(data[i][2]),
      delegateMain: (data[i][5] || "").toString().trim(),
      phoneMain: (data[i][6] || "").toString().trim(),
      delegateAlt: (data[i][7] || "").toString().trim(),
      phoneAlt: (data[i][8] || "").toString().trim()
    });
  }
  return result;
}

function saveData(number, section, center, committee, performedBy) {
  if (!number || !section || !center || !committee) {
    return { status: "error", msg: "من فضلك أكمل كل الحقول" };
  }

  const lock = LockService.getScriptLock();
  try {
    lock.waitLock(20000);
  } catch (err) {
    return { status: "error", msg: "النظام مشغول حاليًا، برجاء المحاولة مرة أخرى خلال ثوانٍ" };
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName("Data");
    if (!sheet) throw new Error("Sheet 'Data' غير موجود");

    const now = new Date();
    const currentHour = Utilities.formatDate(now, Session.getScriptTimeZone(), "yyyy-MM-dd HH");

    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      const rowDate = data[i][0];
      const rowCommittee = normalize(data[i][3]);
      const rowHour = Utilities.formatDate(new Date(rowDate), Session.getScriptTimeZone(), "yyyy-MM-dd HH");

      if (rowCommittee == normalize(committee) && rowHour === currentHour) {
        logAction(performedBy, section, "save-data-failed", `محاولة إضافة رقم ${number} إلى لجنة ${committee} خلال نفس الساعة`);
        return { status: "error", msg: "تمت الإضافة بالفعل لهذه اللجنة خلال هذه الساعة" };
      }
    }

    sheet.appendRow([now, section, center, committee, number]);
    logAction(performedBy, section, "save-data", `تم إضافة رقم ${number} إلى لجنة ${committee}`);
    return { status: "success", msg: "تمت الإضافة بنجاح" };
  } finally {
    lock.releaseLock();
  }
}

function getCommitteesForPanel(section) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const electionSheet = ss.getSheetByName("Election_July");
  const codesSheet = ss.getSheetByName("Codes");

  const electionData = electionSheet.getDataRange().getValues();
  const codesData = codesSheet.getDataRange().getValues();
  const today = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyy-MM-dd");

  const committees = [];
  for (let i = 1; i < electionData.length; i++) {
    const rowSection = normalize(electionData[i][0]);
    if (!section || rowSection === normalize(section)) {
      committees.push(normalize(electionData[i][2]));
    }
  }

  const openedCommittees = new Set();
  for (let i = 1; i < codesData.length; i++) {
    const committee = normalize(codesData[i][10]); // K
    const openValue = normalize(codesData[i][11]); // L
    const openTime = codesData[i][12]; // M

    if (openValue && Utilities.formatDate(new Date(openTime), Session.getScriptTimeZone(), "yyyy-MM-dd") === today) {
      openedCommittees.add(committee);
    }
  }

  return committees.filter(c => !openedCommittees.has(c));
}

function saveCommitteeOpen(username, committeeNumber, value) {
  const lock = LockService.getScriptLock();
  try {
    lock.waitLock(20000);
  } catch (err) {
    return { status: "error", msg: "النظام مشغول حاليًا، برجاء المحاولة مرة أخرى خلال ثوانٍ" };
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName("Codes");
    const data = sheet.getDataRange().getValues();
    const today = new Date();

    for (let i = 1; i < data.length; i++) {
      const committee = normalize(data[i][10]);
      if (committee == normalize(committeeNumber)) {
        sheet.getRange(i + 1, 12).setValue(value);
        sheet.getRange(i + 1, 13).setValue(today);
        sheet.getRange(i + 1, 14).setValue(username);
        logAction(username, "", "open-committee", `تم فتح اللجنة ${committeeNumber}`);
        return { status: "success", msg: "تم تسجيل فتح اللجنة بنجاح" };
      }
    }
    logAction(username, "", "open-committee-failed", `فشل فتح اللجنة ${committeeNumber}`);
    return { status: "error", msg: "لم يتم العثور على اللجنة" };
  } finally {
    lock.releaseLock();
  }
}

function getAdminDashboard() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const dataSheet = ss.getSheetByName("Data");
  const codesSheet = ss.getSheetByName("Codes");
  const electionSheet = ss.getSheetByName("Election_July");
  const today = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyy-MM-dd");
  const data = dataSheet.getDataRange().getValues();
  const codesData = codesSheet.getDataRange().getValues();
  const electionData = electionSheet.getDataRange().getValues();

  let totalEntries = 0;
  let entriesByHour = {};
  let openCommittees = 0;
  let closedCommittees = 0;
  let openActions = [];
  let sectionMap = {};
  let openedCommittees = new Set();

  for (let i = 1; i < electionData.length; i++) {
    const section = normalize(electionData[i][0]);
    const committee = normalize(electionData[i][2]);
    if (!section || !committee) continue;
    if (!sectionMap[section]) {
      sectionMap[section] = {
        section: section,
        totalCommittees: new Set(),
        openCommittees: 0,
        closedCommittees: 0,
        entries: 0
      };
    }
    sectionMap[section].totalCommittees.add(committee);
  }

  for (let i = 1; i < codesData.length; i++) {
    const openValue = normalize(codesData[i][11]);
    const openTime = codesData[i][12];
    const committee = normalize(codesData[i][10]);

    if (openValue && openTime && Utilities.formatDate(new Date(openTime), Session.getScriptTimeZone(), "yyyy-MM-dd") === today) {
      openedCommittees.add(committee);
      openCommittees++;
      openActions.push({
        committee: committee,
        openedBy: (codesData[i][13] || "غير معروف").toString().trim(),
        openedAt: Utilities.formatDate(new Date(openTime), Session.getScriptTimeZone(), "HH:mm")
      });
    }
  }

  for (let sectionKey in sectionMap) {
    const info = sectionMap[sectionKey];
    info.openCommittees = [...info.totalCommittees].filter(c => openedCommittees.has(c)).length;
    info.closedCommittees = info.totalCommittees.size - info.openCommittees;
  }

  for (let i = 1; i < data.length; i++) {
    const rowDate = data[i][0];
    if (!rowDate) continue;
    const rowDateString = Utilities.formatDate(new Date(rowDate), Session.getScriptTimeZone(), "yyyy-MM-dd");
    if (rowDateString !== today) continue;

    const rowHour = Utilities.formatDate(new Date(rowDate), Session.getScriptTimeZone(), "yyyy-MM-dd HH");
    totalEntries++;
    entriesByHour[rowHour] = (entriesByHour[rowHour] || 0) + 1;

    const section = normalize(data[i][1]);
    if (sectionMap[section]) {
      sectionMap[section].entries++;
    } else if (section) {
      sectionMap[section] = {
        section: section,
        totalCommittees: new Set(),
        openCommittees: 0,
        closedCommittees: 0,
        entries: 1
      };
    }
  }

  closedCommittees = Math.max(0, Object.values(sectionMap).reduce((sum, info) => sum + info.closedCommittees, 0));

  return {
    totalEntries: totalEntries,
    openCommittees: openCommittees,
    closedCommittees: closedCommittees,
    entriesByHour: entriesByHour,
    openActions: openActions,
    sectionStats: Object.values(sectionMap).map(info => ({
      section: info.section,
      totalCommittees: info.totalCommittees.size,
      openCommittees: info.openCommittees,
      closedCommittees: info.closedCommittees,
      entries: info.entries
    }))
  };
}

// ==================== إدارة المستخدمين والصلاحيات ====================

function saveUserPermission(username, password, section, role, capabilities, performedBy) {
  const lock = LockService.getScriptLock();
  lock.waitLock(15000);
  try {
    const sheet = getPermissionsSheet();
    if (!sheet) {
      return { success: false, msg: "لم يتم العثور على شيت صلاحيات المستخدمين" };
    }
    ensurePermissionColumns(sheet);

    const data = sheet.getDataRange().getValues();
    if (!data || data.length === 0) {
      return { success: false, msg: "شيت الصلاحيات فارغ" };
    }

    const headers = data[0];
    const userIdx = findColumnIndex(headers, ["اسم المستخدم", "USER"]);
    const passIdx = findColumnIndex(headers, ["كلمة المرور", "PASSWORD", "PASS"]);
    const saltIdx = findColumnIndex(headers, ["الملح", "SALT"]);
    const sectionIdx = findColumnIndex(headers, ["القسم", "SECTION"]);
    const roleIdx = findColumnIndex(headers, ["الصلاحية", "ROLE"]);
    const capsIdx = findColumnIndex(headers, ["الصلاحيات التفصيلية", "CAPABILITIES"]);
    const loginTimeIdx = findColumnIndex(headers, ["آخر تسجيل دخول", "LAST LOGIN", "LOGIN"]);

    if (userIdx === -1 || sectionIdx === -1 || roleIdx === -1) {
      return { success: false, msg: "عناوين الأعمدة غير مكتملة في شيت الصلاحيات" };
    }

    const normalizedUser = normalize(username);
    const capsToSave = JSON.stringify(capabilities && Object.keys(capabilities).length ? capabilities : defaultCapabilitiesForRole(role));

    let foundRow = -1;
    for (let i = 1; i < data.length; i++) {
      if (normalize(data[i][userIdx]) === normalizedUser) {
        foundRow = i;
        break;
      }
    }

    if (foundRow === -1) {
      if (!password) {
        return { success: false, msg: "كلمة المرور مطلوبة عند إضافة مستخدم جديد" };
      }
      const newSalt = generateSalt();
      const newHash = hashPassword(password, newSalt);

      const newRow = new Array(headers.length).fill("");
      newRow[userIdx] = username;
      if (passIdx !== -1) newRow[passIdx] = newHash;
      if (saltIdx !== -1) newRow[saltIdx] = newSalt;
      newRow[sectionIdx] = section;
      newRow[roleIdx] = role;
      if (capsIdx !== -1) newRow[capsIdx] = capsToSave;
      if (loginTimeIdx !== -1) newRow[loginTimeIdx] = "";
      sheet.appendRow(newRow);
      logAction(performedBy, section, "save-permission", `تم إضافة مستخدم جديد ${username} بالصلاحية ${role}`);
      return { success: true, msg: "تم إضافة المستخدم بنجاح" };
    }

    if (password) {
      const newSalt = generateSalt();
      const newHash = hashPassword(password, newSalt);
      if (passIdx !== -1) sheet.getRange(foundRow + 1, passIdx + 1).setValue(newHash);
      if (saltIdx !== -1) sheet.getRange(foundRow + 1, saltIdx + 1).setValue(newSalt);
    }
    sheet.getRange(foundRow + 1, sectionIdx + 1).setValue(section);
    sheet.getRange(foundRow + 1, roleIdx + 1).setValue(role);
    if (capsIdx !== -1) sheet.getRange(foundRow + 1, capsIdx + 1).setValue(capsToSave);
    logAction(performedBy, section, "update-permission", `تم تعديل صلاحية المستخدم ${username} إلى ${role}`);
    return { success: true, msg: "تم تحديث بيانات المستخدم بنجاح" };
  } finally {
    lock.releaseLock();
  }
}

function getUserPermissions() {
  const sheet = getPermissionsSheet();
  if (!sheet) return [];
  ensurePermissionColumns(sheet);

  const data = sheet.getDataRange().getValues();
  if (!data || data.length < 2) return [];

  const headers = data[0];
  const userIdx = findColumnIndex(headers, ["اسم المستخدم", "USER"]);
  const sectionIdx = findColumnIndex(headers, ["القسم", "SECTION"]);
  const roleIdx = findColumnIndex(headers, ["الصلاحية", "ROLE"]);
  const capsIdx = findColumnIndex(headers, ["الصلاحيات التفصيلية", "CAPABILITIES"]);
  const permissions = [];

  for (let i = 1; i < data.length; i++) {
    const role = roleIdx !== -1 ? normalize(data[i][roleIdx]) : "USER";
    permissions.push({
      username: userIdx !== -1 ? normalize(data[i][userIdx]) : "",
      section: sectionIdx !== -1 ? normalize(data[i][sectionIdx]) : "",
      role: role,
      capabilities: parseCapabilities(capsIdx !== -1 ? data[i][capsIdx] : "", role)
      // ملاحظة: لا يتم إرجاع كلمة المرور أو الملح أبدًا للواجهة الأمامية
    });
  }
  return permissions;
}

// ==================== مراجعة الشيتات (مع حماية شيت الصلاحيات) ====================

function isMirrorSheetAllowed(sheetName) {
  return CONFIG.ALLOWED_MIRROR_SHEETS.indexOf(sheetName) !== -1;
}

// يستبدل قيم أي عمود حساس (كلمة مرور/ملح) بنجوم قبل إرسال البيانات للواجهة
function redactSensitiveColumns(values) {
  if (!values || values.length === 0) return values;
  const headers = values[0];
  const sensitiveIdxs = findAllColumnIndices(headers, CONFIG.SENSITIVE_COLUMN_PATTERNS);
  if (sensitiveIdxs.length === 0) return values;

  return values.map((row, rowIndex) => {
    if (rowIndex === 0) return row; // اترك صف العناوين كما هو
    const newRow = row.slice();
    sensitiveIdxs.forEach(idx => {
      if (newRow[idx]) newRow[idx] = "••••••••";
    });
    return newRow;
  });
}

function getSheetDataMirror(sheetName, performedBy) {
  if (!isMirrorSheetAllowed(sheetName)) {
    return null;
  }
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet) return null;
  logAction(performedBy, '', 'open-sheet', `تم فتح شيت ${sheetName}`);
  const values = sheet.getDataRange().getDisplayValues();
  return redactSensitiveColumns(values);
}

function getFinalMatrixData(section) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName("Election_July");
  if (!sheet) return [];

  const data = sheet.getDataRange().getValues();
  let matrixData = [];

  for (let i = 1; i < data.length; i++) {
    let rowSection = normalize(data[i][0]); // A
    if (!section || rowSection === normalize(section)) {
      matrixData.push({
        center: normalize(data[i][1]),    // B
        committee: normalize(data[i][2]), // C
        total: data[i][21] || 0           // V
      });
    }
  }
  return matrixData;
}

// === Generate a mirror CSV report containing key sheets (Codes, Data, Election_July, الاجمالي)
function downloadAdminReport(performedBy) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheetNames = ['Codes', 'Data', 'Election_July', 'الاجمالي'];
  let parts = [];
  logAction(performedBy || "", "", "download-admin-report", "تم تنزيل تقرير الميرور");

  sheetNames.forEach(name => {
    const sh = ss.getSheetByName(name);
    if (!sh) return;
    let values = sh.getDataRange().getDisplayValues();
    values = redactSensitiveColumns(values);
    parts.push([`# SHEET: ${name}`]);
    if (values && values.length) {
      values.forEach(row => {
        const sanitized = row.map(cell => {
          const txt = (cell || '').toString();
          if (txt.indexOf(',') !== -1 || txt.indexOf('"') !== -1 || txt.indexOf('\n') !== -1) {
            return '"' + txt.replace(/"/g, '""') + '"';
          }
          return txt;
        });
        parts.push(sanitized);
      });
    }
    parts.push([]);
  });

  const csvRows = parts.map(r => r.join(',')).join('\n');
  const fileName = 'mirror_report_' + Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyyMMdd_HHmm') + '.csv';
  const csvBase64 = Utilities.base64Encode(csvRows);

  return { success: true, filename: fileName, csvBase64: csvBase64 };
}

function downloadSheetReport(sheetName, performedBy) {
  if (!sheetName) {
    return { success: false, msg: 'اسم الشيت مطلوب' };
  }
  if (!isMirrorSheetAllowed(sheetName)) {
    return { success: false, msg: 'غير مسموح بتنزيل هذا الشيت' };
  }
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet) {
    return { success: false, msg: 'الشيت غير موجود' };
  }
  logAction(performedBy || "", "", "download-sheet-report", `تم تنزيل شيت ${sheetName}`);
  let values = sheet.getDataRange().getDisplayValues();
  if (!values || values.length === 0) {
    return { success: false, msg: 'الشيت فارغ' };
  }
  values = redactSensitiveColumns(values);

  const csvRows = values.map(row => {
    return row.map(cell => {
      const txt = (cell || '').toString();
      if (txt.indexOf(',') !== -1 || txt.indexOf('"') !== -1 || txt.indexOf('\n') !== -1) {
        return '"' + txt.replace(/"/g, '""') + '"';
      }
      return txt;
    }).join(',');
  }).join('\n');

  const fileName = sheetName + '_' + Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyyMMdd_HHmm') + '.csv';
  return { success: true, filename: fileName, csvBase64: Utilities.base64Encode(csvRows) };
}
