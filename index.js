// 🌐 متغیرهای محیطی
const ADMIN_USER_IDS = JSON.parse(ADMIN_USER_IDS_JSON || "[123456789]");

// 🧮 توابع کمکی
function escapeMarkdown(text) {
    if (!text) return "";
    return text.replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
}

function generateSecurePassword(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=';
    let password = '';
    password += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)];
    password += 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)];
    password += '0123456789'[Math.floor(Math.random() * 10)];
    password += '!@#$%^&*()_+~`|}{[]:;?><,./-='[Math.floor(Math.random() * 30)];
    for (let i = 4; i < length; i++) {
        password += chars[Math.floor(Math.random() * chars.length)];
    }
    return password.split('').sort(() => Math.random() - 0.5).join('');
}

function checkPasswordStrength(password) {
    let strength = 0;
    let feedback = [];
    if (password.length >= 12) strength += 2;
    else if (password.length >= 8) strength += 1;
    else feedback.push("حداقل 8 کاراکتر");
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) strength += 1;
    else feedback.push("ترکیب حروف بزرگ و کوچک");
    if (/[0-9]/.test(password)) strength += 1;
    else feedback.push("شامل عدد");
    if (/[^A-Za-z0-9]/.test(password)) strength += 1;
    else feedback.push("شامل کاراکتر خاص");
    const commonPasswords = ["password", "123456", "qwerty", "admin", "welcome"];
    if (commonPasswords.includes(password.toLowerCase())) {
        strength = 0;
        feedback.push("رمز رایج - تغییر دهید!");
    }
    const levels = ["ضعیف", "متوسط", "قوی", "بسیار قوی"];
    return { strength: levels[Math.min(strength, 3)], score: `${strength}/4`, feedback };
}

function validateEmail(email) {
    const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!re.test(email)) return "❌ فرمت ایمیل نامعتبر است.";
    return "✅ ایمیل معتبر است (فرمت)";
}

async function analyzeUrl(url) {
    try {
        const parsed = new URL(url.startsWith('http') ? url : 'https://' + url);
        const analysis = {
            hasHttps: parsed.protocol === 'https:',
            hasIpAddress: /\d+\.\d+\.\d+\.\d+/.test(parsed.hostname),
            isShortened: ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com'].some(d => parsed.hostname.includes(d)),
            suspiciousKeywords: ['login', 'secure', 'account', 'verify', 'banking'].some(k => parsed.pathname.includes(k)),
            length: url.length,
            riskScore: 0
        };
        if (!analysis.hasHttps) analysis.riskScore += 1;
        if (analysis.hasIpAddress) analysis.riskScore += 2;
        if (analysis.isShortened) analysis.riskScore += 1;
        if (analysis.suspiciousKeywords) analysis.riskScore += 1;
        if (analysis.length > 100) analysis.riskScore += 1;
        analysis.riskLevel = analysis.riskScore <= 2 ? "کم" : analysis.riskScore <= 4 ? "متوسط" : "بالا";
        return analysis;
    } catch (e) {
        return { error: "URL نامعتبر" };
    }
}

// 🔢 اعتبارسنجی دقیق کد ملی ایران
function validateNationalCode(code) {
    if (!code || typeof code !== 'string') {
        return { valid: false, message: "کد ملی باید یک رشته باشد" };
    }
    
    const cleanedCode = code.replace(/\s/g, '').replace(/\D/g, '');
    
    if (cleanedCode.length !== 10) {
        return { valid: false, message: "کد ملی باید 10 رقمی باشد" };
    }
    
    if (/^(\d)\1{9}$/.test(cleanedCode)) {
        return { valid: false, message: "کد ملی معتبر نیست (همه ارقام یکسان)" };
    }
    
    const digits = cleanedCode.split('').map(Number);
    const checkDigit = digits[9];
    
    let sum = 0;
    for (let i = 0; i < 9; i++) {
        sum += digits[i] * (10 - i);
    }
    
    const remainder = sum % 11;
    const isValid = (remainder < 2 && checkDigit === remainder) || 
                   (remainder >= 2 && checkDigit === 11 - remainder);
    
    if (!isValid) {
        return { valid: false, message: "کد ملی معتبر نیست" };
    }
    
    return { valid: true, message: "کد ملی معتبر است" };
}

// 🗺️ پایگاه داده کدهای شهرستان‌های ایران
const NATIONAL_CODE_PREFIXES = [
    { code_prefix: "001", province: "تهران", city: "مرکزی" },
    { code_prefix: "002", province: "تهران", city: "شهرری" },
    { code_prefix: "003", province: "تهران", city: "ورامین" },
    { code_prefix: "004", province: "تهران", city: "شمیران" },
    { code_prefix: "005", province: "تهران", city: "اسلامشهر" },
    { code_prefix: "006", province: "تهران", city: "رباط کریم" },
    { code_prefix: "007", province: "تهران", city: "پاکدشت" },
    { code_prefix: "008", province: "تهران", city: "فیروزکوه" },
    { code_prefix: "009", province: "تهران", city: "دماوند" },
    { code_prefix: "010", province: "تهران", city: "شهریار" },
    { code_prefix: "011", province: "گیلان", city: "مرکزی" },
    { code_prefix: "012", province: "گیلان", city: "رشت" },
    { code_prefix: "013", province: "گیلان", city: "لاهیجان" },
    { code_prefix: "014", province: "گیلان", city: "تالش" },
    { code_prefix: "015", province: "گیلان", city: "انزلی" },
    { code_prefix: "016", province: "گیلان", city: "آستارا" },
    { code_prefix: "017", province: "گیلان", city: "رودبار" },
    { code_prefix: "018", province: "گیلان", city: "فومن" },
    { code_prefix: "019", province: "گیلان", city: "صومعه سرا" },
    { code_prefix: "020", province: "گیلان", city: "املش" },
    { code_prefix: "021", province: "مازندران", city: "مرکزی" },
    { code_prefix: "022", province: "مازندران", city: "ساری" },
    { code_prefix: "023", province: "مازندران", city: "بابل" },
    { code_prefix: "024", province: "مازندران", city: "آمل" },
    { code_prefix: "025", province: "مازندران", city: "نور" },
    { code_prefix: "026", province: "مازندران", city: "نوشهر" },
    { code_prefix: "027", province: "مازندران", city: "تنکابن" },
    { code_prefix: "028", province: "مازندران", city: "رامسر" },
    { code_prefix: "029", province: "مازندران", city: "محمودآباد" },
    { code_prefix: "030", province: "مازندران", city: "جویبار" },
];

async function getNationalCodeLocation(code) {
    if (!code || code.length < 3) return null;
    const prefix = code.substring(0, 3);
    return NATIONAL_CODE_PREFIXES.find(item => item.code_prefix === prefix) || null;
}

// 💳 استعلام شماره کارت
async function inquiryCardNumber(cardNumber) {
    try {
        const cleanedCardNumber = cardNumber.replace(/\s/g, '');
        if (!/^\d{16}$/.test(cleanedCardNumber)) {
            return { success: false, error: "شماره کارت باید 16 رقمی باشد" };
        }

        const url = "https://my.tabdilcard.com/back/api/v1/user-b2c/service/bank/accountBlockingCard/preview";
        const payload = {
            type: 16,
            card: cleanedCardNumber,
            paymentMethod: 1
        };
        const headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "authorization": "Bearer undefined",
            "x-referer": "https://my.tabdilcard.com"
        };

        const response = await fetch(url, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(payload)
        });

        if (response.status === 200 || response.status === 201) {
            const data = await response.json();
            if (data && data.result) {
                return {
                    success: true,
                    bankName: data.result.bankName || "نامشخص",
                    depositOwners: data.result.depositOwners || "نامشخص",
                    trackingCode: data.trackingCode || "نامشخص"
                };
            }
        }
        return { success: false, error: `خطا ${response.status}` };
    } catch (error) {
        return { success: false, error: "خطا در ارتباط با سرور" };
    }
}

// 🔐 توابع رمزنگاری
async function hashText(text, algorithm = 'SHA-256') {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest(algorithm, data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64Encode(str) {
    return btoa(unescape(encodeURIComponent(str)));
}

function base64Decode(str) {
    try {
        return decodeURIComponent(escape(atob(str)));
    } catch (e) {
        return "❌ خطا در دیکد کردن Base64";
    }
}

function rot13(str) {
    return str.replace(/[a-zA-Z]/g, function(c) {
        return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);
    });
}

function caesarCipher(str, shift = 3) {
    return str.replace(/[a-zA-Z]/g, function(c) {
        const base = c <= 'Z' ? 'A'.charCodeAt(0) : 'a'.charCodeAt(0);
        return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
    });
}

function textToBinary(str) {
    return str.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
}

function binaryToText(binaryStr) {
    return binaryStr.split(' ').map(bin => String.fromCharCode(parseInt(bin, 2))).join('');
}

// 📊 مدیریت کاربران و محدودیت‌ها
async function addUser(user) {
    const now = new Date().toISOString();
    const isAdmin = ADMIN_USER_IDS.includes(user.id) ? 1 : 0;
    
    const userData = {
        user_id: user.id,
        username: user.username,
        first_name: user.first_name,
        last_name: user.last_name,
        join_date: now,
        is_admin: isAdmin,
        usage_count: 0,
        last_used: now
    };
    
    await USERS.put(`user_${user.id}`, JSON.stringify(userData));
    await USERS.put(`rate_${user.id}`, JSON.stringify({
        user_id: user.id,
        request_count: 1,
        last_request: now,
        banned_until: null
    }));
}

async function checkRateLimit(user_id) {
    const rateData = await USERS.get(`rate_${user_id}`, 'json');
    if (!rateData) return { allowed: true };
    
    const now = new Date();
    if (rateData.banned_until && now < new Date(rateData.banned_until)) {
        return { allowed: false, bannedUntil: new Date(rateData.banned_until) };
    }
    
    const lastRequest = new Date(rateData.last_request);
    const timeDiff = now - lastRequest;
    
    if (timeDiff > 60000) {
        await USERS.put(`rate_${user_id}`, JSON.stringify({
            ...rateData,
            request_count: 1,
            last_request: now.toISOString()
        }));
        return { allowed: true };
    }
    
    if (rateData.request_count >= 5) {
        const bannedUntil = new Date(now.getTime() + 3600000);
        await USERS.put(`rate_${user_id}`, JSON.stringify({
            ...rateData,
            banned_until: bannedUntil.toISOString()
        }));
        return { allowed: false, bannedUntil };
    }
    
    await USERS.put(`rate_${user_id}`, JSON.stringify({
        ...rateData,
        request_count: rateData.request_count + 1,
        last_request: now.toISOString()
    }));
    
    return { allowed: true };
}

async function updateUsage(user_id, command, details = null) {
    const userData = await USERS.get(`user_${user_id}`, 'json');
    if (userData) {
        await USERS.put(`user_${user_id}`, JSON.stringify({
            ...userData,
            usage_count: (userData.usage_count || 0) + 1,
            last_used: new Date().toISOString()
        }));
    }
    
    const logId = Date.now();
    await USERS.put(`log_${logId}`, JSON.stringify({
        user_id,
        command,
        timestamp: new Date().toISOString(),
        details
    }));
}

async function getUserStats(user_id) {
    const userData = await USERS.get(`user_${user_id}`, 'json');
    return userData ? {
        usage_count: userData.usage_count || 0,
        last_used: userData.last_used
    } : null;
}

async function isAdmin(user_id) {
    const userData = await USERS.get(`user_${user_id}`, 'json');
    return userData && userData.is_admin === 1;
}

// 🤖 توابع ربات تلگرام
async function sendTelegramMessage(chatId, text, replyMarkup = null) {
    const apiUrl = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
    const body = {
        chat_id: chatId,
        text: text,
        parse_mode: "Markdown",
        ...(replyMarkup && { reply_markup: JSON.stringify(replyMarkup) })
    };

    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        return await response.json();
    } catch (error) {
        console.error("Error sending message:", error);
        return null;
    }
}

async function editTelegramMessage(chatId, messageId, text, replyMarkup = null) {
    const apiUrl = `https://api.telegram.org/bot${BOT_TOKEN}/editMessageText`;
    const body = {
        chat_id: chatId,
        message_id: messageId,
        text: text,
        parse_mode: "Markdown",
        ...(replyMarkup && { reply_markup: JSON.stringify(replyMarkup) })
    };

    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        return await response.json();
    } catch (error) {
        console.error("Error editing message:", error);
        return null;
    }
}

async function answerCallbackQuery(callbackQueryId, text = "", showAlert = false) {
    const apiUrl = `https://api.telegram.org/bot${BOT_TOKEN}/answerCallbackQuery`;
    const body = {
        callback_query_id: callbackQueryId,
        text: text,
        show_alert: showAlert
    };

    try {
        await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
    } catch (error) {
        console.error("Error answering callback:", error);
    }
}

// 🧠 پردازش ورودی کاربر
async function processUserInput(chatId, userId, action, input) {
    let responseText = "";
    let commandDetails = input;

    try {
        if (action === 'national_code_check') {
            const validation = validateNationalCode(input);
            if (!validation.valid) {
                responseText = `❌ ${validation.message}`;
            } else {
                const location = await getNationalCodeLocation(input);
                responseText = `✅ ${validation.message}`;
                if (location) {
                    responseText += `\n• استان: ${location.province}\n• شهر: ${location.city}`;
                } else {
                    responseText += "\n• استان/شهر: نامشخص";
                }
            }
        } else if (action === 'card_inquiry') {
            const result = await inquiryCardNumber(input);
            if (result.success) {
                responseText = `✅ اطلاعات کارت:
• بانک: ${result.bankName}
• صاحب حساب: ${result.depositOwners}
• کد رهگیری: ${result.trackingCode}`;
            } else {
                responseText = `❌ ${result.error}`;
            }
        } else if (action === 'email_validator') {
            responseText = validateEmail(input);
        } else if (action === 'url_analyzer') {
            const result = await analyzeUrl(input);
            if (result.error) {
                responseText = `❌ ${result.error}`;
            } else {
                responseText = `🔗 تحلیل URL:
• HTTPS: ${result.hasHttps ? '✅' : '❌'}
• سطح ریسک: ${result.riskLevel}
• امتیاز ریسک: ${result.riskScore}/6`;
            }
        } else if (action === 'generate_password') {
            const length = Math.min(50, Math.max(8, parseInt(input) || 16));
            const password = generateSecurePassword(length);
            responseText = `🔐 رمز تولید شده (${length} کاراکتر):
\`${password}\``;
            commandDetails = `length:${length}`;
        } else if (action === 'password_strength') {
            const result = checkPasswordStrength(input);
            let feedbackText = result.feedback.length > 0 ? 
                "\n• پیشنهادات:\n" + result.feedback.map(f => `  - ${f}`).join('\n') : '';
            responseText = `🔐 قدرت رمز:
• سطح: ${result.strength}
• امتیاز: ${result.score}${feedbackText}`;
            commandDetails = '***';
        } else if (action === 'base64_encode') {
            const encoded = base64Encode(input);
            responseText = `🔣 Base64 Encode:
\`${encoded}\``;
        } else if (action === 'base64_decode') {
            const decoded = base64Decode(input);
            responseText = `🔣 Base64 Decode:
\`${decoded}\``;
        } else if (action === 'md5_hash') {
            const hashed = await hashText(input, 'MD5');
            responseText = `🔢 MD5 Hash:
\`${hashed}\``;
        } else if (action === 'sha256_hash') {
            const hashed = await hashText(input, 'SHA-256');
            responseText = `🔢 SHA256 Hash:
\`${hashed}\``;
        } else if (action === 'rot13_encode') {
            const encoded = rot13(input);
            responseText = `🔄 ROT13:
\`${encoded}\``;
        } else if (action === 'caesar_cipher') {
            const [text, shiftStr] = input.split(':');
            const shift = parseInt(shiftStr) || 3;
            const encoded = caesarCipher(text, shift);
            responseText = `🔠 Caesar Cipher (Shift=${shift}):
\`${encoded}\``;
            commandDetails = `shift:${shift}`;
        } else if (action === 'binary_encode') {
            const encoded = textToBinary(input);
            responseText = `💻 Binary Encode:
\`${encoded}\``;
        } else if (action === 'binary_decode') {
            const decoded = binaryToText(input);
            responseText = `💻 Binary Decode:
\`${decoded}\``;
        } else {
            responseText = "❌ دستور نامعتبر";
        }
    } catch (error) {
        responseText = `❌ خطا: ${error.message}`;
    }

    await updateUsage(userId, action, commandDetails);
    return responseText;
}

// 🎛️ مدیریت منوها
async function showMainMenu(chatId, firstName, messageId = null) {
    const text = `سلام ${firstName}! 👋
به **ربات خدمات عمومی و امنیتی** خوش آمدید!
از منوی زیر انتخاب کنید:`;

    const keyboard = {
        inline_keyboard: [
            [{ text: "🔍 ابزارهای امنیتی", callback_data: "security_tools" }],
            [{ text: "🔐 ابزارهای رمزنگاری", callback_data: "encryption_tools" }],
            [{ text: "📋 ابزارهای عمومی", callback_data: "general_tools" }],
            [{ text: "ℹ️ اطلاعات حساب", callback_data: "account_info" }]
        ]
    };

    if (messageId) {
        await editTelegramMessage(chatId, messageId, text, keyboard);
    } else {
        await sendTelegramMessage(chatId, text, keyboard);
    }
}

async function showGeneralTools(chatId, messageId) {
    const text = "📋 ابزارهای عمومی:\nلطفاً یکی از گزینه‌ها را انتخاب کنید:";

    const keyboard = {
        inline_keyboard: [
            [{ text: "🆔 اعتبارسنجی کد ملی", callback_data: "national_code_check" }],
            [{ text: "💳 استعلام شماره کارت", callback_data: "card_inquiry" }],
            [{ text: "📧 اعتبارسنجی ایمیل", callback_data: "email_validator" }],
            [{ text: "🔗 آنالیز URL", callback_data: "url_analyzer" }],
            [{ text: "🔙 بازگشت", callback_data: "main_menu" }]
        ]
    };

    await editTelegramMessage(chatId, messageId, text, keyboard);
}

async function showSecurityTools(chatId, messageId) {
    const text = "🔍 ابزارهای امنیتی:\nلطفاً یکی از گزینه‌ها را انتخاب کنید:";

    const keyboard = {
        inline_keyboard: [
            [{ text: "🔐 تولید رمز عبور", callback_data: "generate_password" }],
            [{ text: "📊 بررسی قدرت رمز", callback_data: "password_strength" }],
            [{ text: "🔙 بازگشت", callback_data: "main_menu" }]
        ]
    };

    await editTelegramMessage(chatId, messageId, text, keyboard);
}

async function showEncryptionTools(chatId, messageId) {
    const text = "🔐 ابزارهای رمزنگاری:\nلطفاً یکی از گزینه‌ها را انتخاب کنید:";

    const keyboard = {
        inline_keyboard: [
            [{ text: "🔣 Base64 Encode", callback_data: "base64_encode" }],
            [{ text: "🔣 Base64 Decode", callback_data: "base64_decode" }],
            [{ text: "🔢 MD5 Hash", callback_data: "md5_hash" }],
            [{ text: "🔢 SHA256 Hash", callback_data: "sha256_hash" }],
            [{ text: "🔄 ROT13", callback_data: "rot13_encode" }],
            [{ text: "🔠 Caesar Cipher", callback_data: "caesar_cipher" }],
            [{ text: "💻 Binary Encode", callback_data: "binary_encode" }],
            [{ text: "💻 Binary Decode", callback_data: "binary_decode" }],
            [{ text: "🔙 بازگشت", callback_data: "main_menu" }]
        ]
    };

    await editTelegramMessage(chatId, messageId, text, keyboard);
}

// 🎯 مدیریت کلیک‌ها
async function handleCallback(update) {
    const callback = update.callback_query;
    const chatId = callback.message.chat.id;
    const messageId = callback.message.message_id;
    const user = callback.from;
    const data = callback.data;

    await addUser(user);
    const userIsAdmin = await isAdmin(user.id);
    
    const rateCheck = await checkRateLimit(user.id);
    if (!rateCheck.allowed) {
        const remaining = Math.floor((rateCheck.bannedUntil - new Date()) / 1000);
        const hours = Math.floor(remaining / 3600);
        const minutes = Math.floor((remaining % 3600) / 60);
        const seconds = remaining % 60;
        await answerCallbackQuery(callback.id, `⛔ محدود شدید!\nزمان باقیمانده: ${hours} ساعت ${minutes} دقیقه ${seconds} ثانیه`, true);
        return;
    }

    await answerCallbackQuery(callback.id);

    if (data === 'main_menu') {
        await showMainMenu(chatId, user.first_name, messageId);
    } else if (data === 'general_tools') {
        await showGeneralTools(chatId, messageId);
    } else if (data === 'security_tools') {
        await showSecurityTools(chatId, messageId);
    } else if (data === 'encryption_tools') {
        await showEncryptionTools(chatId, messageId);
    } else if (data === 'account_info') {
        const stats = await getUserStats(user.id);
        let lastUsed = "هرگز";
        if (stats && stats.last_used) {
            const date = new Date(stats.last_used);
            lastUsed = `${date.toLocaleDateString('fa-IR')} ${date.toLocaleTimeString('fa-IR')}`;
        }
        const text = `👤 اطلاعات حساب:
• نام: ${user.first_name} ${user.last_name || ''}
• نام کاربری: @${user.username || 'ندارد'}
• تعداد استفاده: ${stats ? stats.usage_count : 0}
• آخرین استفاده: ${lastUsed}`;
        const keyboard = { inline_keyboard: [[{ text: "🔙 بازگشت", callback_data: "main_menu" }]] };
        await editTelegramMessage(chatId, messageId, text, keyboard);
    } else if (['national_code_check', 'card_inquiry', 'email_validator', 'url_analyzer', 
               'generate_password', 'password_strength', 'base64_encode', 'base64_decode', 
               'md5_hash', 'sha256_hash', 'rot13_encode', 'caesar_cipher', 'binary_encode', 'binary_decode'].includes(data)) {
        await USER_STATES.put(`state_${user.id}`, data);
        let prompt = "";
        switch(data) {
            case 'national_code_check': prompt = "لطفاً کد ملی 10 رقمی را وارد کنید:"; break;
            case 'card_inquiry': prompt = "لطفاً شماره کارت 16 رقمی را وارد کنید:"; break;
            case 'email_validator': prompt = "لطفاً ایمیل مورد نظر را وارد کنید:"; break;
            case 'url_analyzer': prompt = "لطفاً URL مورد نظر را وارد کنید:"; break;
            case 'generate_password': prompt = "لطفاً طول رمز (8-50) را وارد کنید (پیش‌فرض: 16):"; break;
            case 'password_strength': prompt = "لطفاً رمز عبور مورد نظر را وارد کنید:"; break;
            case 'base64_encode': prompt = "لطفاً متن برای Encode را وارد کنید:"; break;
            case 'base64_decode': prompt = "لطفاً متن Base64 برای Decode را وارد کنید:"; break;
            case 'md5_hash': prompt = "لطفاً متن برای هش MD5 را وارد کنید:"; break;
            case 'sha256_hash': prompt = "لطفاً متن برای هش SHA256 را وارد کنید:"; break;
            case 'rot13_encode': prompt = "لطفاً متن برای ROT13 را وارد کنید:"; break;
            case 'caesar_cipher': prompt = "لطفاً متن و شیفت را وارد کنید (مثال: hello:3):"; break;
            case 'binary_encode': prompt = "لطفاً متن برای تبدیل به باینری را وارد کنید:"; break;
            case 'binary_decode': prompt = "لطفاً متن باینری برای تبدیل را وارد کنید:"; break;
        }
        await editTelegramMessage(chatId, messageId, prompt);
    } else {
        await editTelegramMessage(chatId, messageId, "❌ دستور نامعتبر است");
    }
}

// 📥 مدیریت پیام‌های متنی
async function handleMessage(update) {
    const message = update.message;
    const chatId = message.chat.id;
    const user = message.from;
    const text = message.text;

    await addUser(user);
    const rateCheck = await checkRateLimit(user.id);
    if (!rateCheck.allowed) {
        const remaining = Math.floor((rateCheck.bannedUntil - new Date()) / 1000);
        const hours = Math.floor(remaining / 3600);
        const minutes = Math.floor((remaining % 3600) / 60);
        const seconds = remaining % 60;
        await sendTelegramMessage(chatId,
            `⛔ محدود شدید!\nزمان باقیمانده: ${hours} ساعت ${minutes} دقیقه ${seconds} ثانیه`
        );
        return;
    }

    const stateKey = `state_${user.id}`;
    const currentState = await USER_STATES.get(stateKey);

    if (currentState) {
        const responseText = await processUserInput(chatId, user.id, currentState, text);
        await USER_STATES.delete(stateKey);
        
        await sendTelegramMessage(chatId, responseText);
        
        const keyboard = { inline_keyboard: [[{ text: "🔙 بازگشت به منوی اصلی", callback_data: "main_menu" }]] };
        await sendTelegramMessage(chatId, "برای بازگشت به منوی اصلی کلیک کنید:", keyboard);
    } else if (text === '/start') {
        await showMainMenu(chatId, user.first_name);
    } else {
        await sendTelegramMessage(chatId, "لطفاً از منوی ربات استفاده کنید. /start");
    }
}

// 🚀 نقطه ورودی اصلی
export default {
    async fetch(request, env) {
        // ذخیره متغیرهای محیطی در scope全局
        globalThis.BOT_TOKEN = env.BOT_TOKEN;
        globalThis.ADMIN_USER_IDS = JSON.parse(env.ADMIN_USER_IDS_JSON || "[123456789]");
        globalThis.USERS = env.USERS;
        globalThis.USER_STATES = env.USER_STATES;
        
        if (request.method === 'POST') {
            try {
                const update = await request.json();
                if (update.message) {
                    await handleMessage(update);
                } else if (update.callback_query) {
                    await handleCallback(update);
                }
                return new Response('OK');
            } catch (error) {
                console.error('Error:', error);
                return new Response('Error processing request', { status: 500 });
            }
        }
        
        return new Response('ربات تلگرام فعال است!');
    }
};