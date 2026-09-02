require('dotenv').config(); // 🟢 สั่งให้ Node.js ไปอ่านไฟล์ .env
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
app.use(cors());

// ==========================================
// 📧 ตั้งค่า Email (Nodemailer)
// ==========================================
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ==========================================
// 📞 STRIPE WEBHOOK (ต้องอยู่ก่อน express.json เสมอ!)
// ==========================================
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

app.post('/api/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    } catch (err) {
        console.error(`⚠️ Webhook Error: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const userId = session.metadata.userId;
        const tier = session.metadata.tier;
        const customerId = session.customer; 

        await User.findByIdAndUpdate(userId, { tier: tier, stripeCustomerId: customerId });
        console.log(`✅ [Webhook] อัปเกรด User: ${userId} เป็น ${tier} (Stripe ID: ${customerId})`);
    }

    if (event.type === 'customer.subscription.deleted') {
        const subscription = event.data.object;
        const customerId = subscription.customer;

        await User.findOneAndUpdate({ stripeCustomerId: customerId }, { tier: 'BASIC' });
        console.log(`❌ [Webhook] ลูกค้ายกเลิก! ปรับ Stripe ID: ${customerId} เป็น BASIC`);
    }

    res.json({received: true});
});

// ==========================================
// ⚙️ ตั้งค่าระบบพื้นฐาน & ฐานข้อมูล
// ==========================================
app.use(express.json()); // 🟢 แปลงข้อมูลเป็น JSON (วางตรงนี้ถูกต้องแล้ว)

const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = '69202104731-mjr9km6etjdslf3ljmkc77bc5nfacekj.apps.googleusercontent.com'; 
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const MONGODB_URI = process.env.MONGODB_URI;

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB Atlas สำเร็จ!'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// 📝 Schema สำหรับ User (แก้บั๊กเพิ่มเครื่องหมาย , ให้แล้ว)
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    tier: { type: String, default: 'BASIC' }, 
    stripeCustomerId: { type: String, default: null },
    autoDownloadsToday: { type: Number, default: 0 },
    manualDownloadsToday: { type: Number, default: 0 },
    lastDownloadDate: { type: String, default: () => new Date().toDateString() },
    isVerified: { type: Boolean, default: false }, 
    otp: { type: String, default: null },
    otpExpires: { type: Date, default: null },
    isTrialActive: { type: Boolean, default: false },
    // 🟢 เพิ่ม 2 บรรทัดนี้ สำหรับระบบโหมดทดลอง (ใช้แล้วหมดไป)
    trialAutoUsed: { type: Number, default: 0 },
    trialManualUsed: { type: Number, default: 0 }
});

const User = mongoose.model('User', userSchema);

// 🛡️ Middleware: เช็ค Token
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access Denied' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid Token' });
        req.user = user;
        next();
    });
};

// ==========================================
// 🚀 API ROUTES
// ==========================================

// 1. สมัครสมาชิก (Register - รอรับ OTP)
// 1. สมัครสมาชิก (Register - รอรับ OTP)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        let user = await User.findOne({ email });

        // สร้าง OTP และเข้ารหัสรหัสผ่านเตรียมไว้
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 15 * 60 * 1000); 
        const hashedPassword = await bcrypt.hash(password, 10);

        if (user) {
            // ถ้ามีอีเมลนี้อยู่แล้ว และยืนยันตัวตนแล้ว = บล็อก
            if (user.isVerified) {
                return res.status(400).json({ message: 'Email already exists' });
            }
            // ถ้ามีอีเมลอยู่ แต่ยังไม่ยืนยัน = อัปเดต OTP ให้ใหม่
            user.name = name;
            user.password = hashedPassword;
            user.otp = otp;
            user.otpExpires = otpExpires;
            await user.save();
        } else {
            // ถ้ายังไม่มีอีเมลนี้เลย = สร้างใหม่
            user = new User({ 
                name, email, password: hashedPassword,
                otp: otp,
                otpExpires: otpExpires
            });
            await user.save();
        }

        // 📧 ลองส่งอีเมล
        try {
           const mailOptions = {
            // 🟢 ใส่ชื่อที่อยากให้โชว์ในเครื่องหมายคำพูด แล้วตามด้วยอีเมลในวงเล็บ < >
            from: '"PixelMe Team 🎨" <' + process.env.EMAIL_USER + '>', 
            to: email,
            subject: '🎨 PixelMe - Verify your email (OTP)',
                html: `<h3>Welcome to PixelMe!</h3>
                       <p>Your verification code is: 
                          <b style="font-size:24px; color:#4285F4;">${otp}</b>
                       </p>
                       <p>This code will expire in 15 minutes.</p>`
            };
            await transporter.sendMail(mailOptions);
            
            // 🟢 ถ้าส่งสำเร็จ จะตอบกลับไปบอกหน้าเว็บให้เปิดกล่อง OTP
            res.status(201).json({ message: 'OTP sent to email' });

        } catch (mailError) {
            // 🔴 ถ้าส่งอีเมลไม่ผ่าน (เช่น ตั้งค่ารหัสผ่าน Gmail ผิด)
            console.error("🚨 Mail Sending Error:", mailError);
            
            // ลบข้อมูลที่เพิ่งสร้างทิ้งไปเลย จะได้ไม่ค้างในระบบ
            await User.deleteOne({ email: email, isVerified: false });
            
            return res.status(500).json({ message: 'Failed to send OTP. Please check server email setup.' });
        }

    } catch (error) {
        console.error("🚨 Server Error:", error);
        res.status(500).json({ message: 'Server error', error });
    }
});

// 2. ตรวจสอบ OTP
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });

        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.isVerified) return res.status(400).json({ message: 'User already verified' });
        
        if (user.otp !== otp || user.otpExpires < new Date()) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        user.isVerified = true;
        user.otp = null;
        user.otpExpires = null;
        await user.save();

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
        const userResponse = user.toObject(); delete userResponse.password;
        
        res.json({ token, user: userResponse, message: 'Verified successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});

// 3. ล็อกอิน (Login)
// 3. ล็อกอิน (Login)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        
        // 🟢 1. ถ้าไม่เจออีเมลในระบบ (อีเมลผิด / ยังไม่ลงทะเบียน)
        if (!user) return res.status(400).json({ message: 'Invalid email or password.' });

        // 🟢 2. ถ้ารหัสผ่านไม่ตรง
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid email or password.' });

        // 🟢 3. ถ้ายังไม่ได้ยืนยัน OTP
        if (!user.isVerified) {
            return res.status(403).json({ message: 'Invalid email or password.' });
        }
        
        const today = new Date().toDateString();
        if (user.lastDownloadDate !== today) {
            user.autoDownloadsToday = 0;
            user.manualDownloadsToday = 0;
            user.lastDownloadDate = today;
            await user.save();
        }

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
        const userResponse = user.toObject(); delete userResponse.password;
        res.json({ token, user: userResponse });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});

// 4. ล็อกอินด้วย Google (Google Login)
app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID 
        });
        
        const payload = ticket.getPayload();
        const { email, name } = payload; 

        let user = await User.findOne({ email });

        if (!user) {
            const randomPassword = await bcrypt.hash(Math.random().toString(36).slice(-8), 10);
            user = new User({
                name: name,
                email: email,
                password: randomPassword,
                tier: 'BASIC',
                isVerified: true, // 🟢 อนุญาตให้ใช้งานได้เลย ไม่ต้องรอ OTP
                autoDownloadsToday: 0,
                manualDownloadsToday: 0,
                lastDownloadDate: new Date().toDateString()
            });
            await user.save();
        } else {
            const today = new Date().toDateString();
            if (user.lastDownloadDate !== today) {
                user.autoDownloadsToday = 0;
                user.manualDownloadsToday = 0;
                user.lastDownloadDate = today;
                await user.save();
            }
        }

        const jwtToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
        const userResponse = user.toObject(); delete userResponse.password;

        res.json({ token: jwtToken, user: userResponse });
    } catch (error) {
        console.error("Google Auth Error:", error);
        res.status(401).json({ message: 'Invalid Google Token' });
    }
});

// 5. ดึงข้อมูล User ปัจจุบัน
app.get('/api/user/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        const today = new Date().toDateString();
        if (user.lastDownloadDate !== today) {
            user.autoDownloadsToday = 0;
            user.manualDownloadsToday = 0;
            user.lastDownloadDate = today;
            await user.save();
        }
        res.json({ user });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// 6. อัปเดตโควต้าเมื่อกดดาวน์โหลด
app.post('/api/user/download', authenticateToken, async (req, res) => {
    try {
        const { tab, amount, useTrial } = req.body; // 🟢 เพิ่ม useTrial
        const user = await User.findById(req.user.id);
        
        if (useTrial && user.isTrialActive) {
            // 🟢 1. ถ้าลูกค้าสลับมาโหมด Trial ให้หักกระเป๋า Trial
            if (tab === 'AUTO') user.trialAutoUsed += amount;
            else user.trialManualUsed += amount;
        } else {
            // 🟢 2. ถ้าอยู่โหมด Basic ปกติ ให้หักกระเป๋ารายวัน
            const today = new Date().toDateString();
            if (user.lastDownloadDate !== today) {
                user.autoDownloadsToday = 0;
                user.manualDownloadsToday = 0;
            }
            if (tab === 'AUTO') user.autoDownloadsToday += amount;
            else user.manualDownloadsToday += amount;
            user.lastDownloadDate = today;
        }

        await user.save();
        res.json({ message: 'Quota updated successfully', user });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// 11. เปิดใช้งานโหมดทดลอง Premium Trial
app.post('/api/user/start-trial', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (user.tier !== 'BASIC') {
            return res.status(400).json({ message: 'Trial is only available for Basic plan users.' });
        }
        if (user.isTrialActive) {
            return res.status(400).json({ message: 'Trial has already been activated for this account.' });
        }
        
        // 🟢 เปลี่ยนแค่สถานะ Trial เป็น True (ไม่เปลี่ยน Tier ผู้ใช้)
        user.isTrialActive = true;
        await user.save();
        res.json({ message: 'Premium Trial activated!', user });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// 7. อัปเกรดแพ็กเกจ (หลังจ่ายเงินสำเร็จ)
app.post('/api/user/upgrade', authenticateToken, async (req, res) => {
    try {
        const { tier, sessionId } = req.body; // 🟢 รับ sessionId มาด้วย
        const user = await User.findById(req.user.id);
        
        user.tier = tier;
        
        // 🟢 ดึงข้อมูล Customer ID จาก Stripe มาบันทึก (สำคัญมากสำหรับปุ่ม Manage)
        if (sessionId) {
            const session = await stripe.checkout.sessions.retrieve(sessionId);
            if (session && session.customer) {
                user.stripeCustomerId = session.customer;
            }
        }
        
        await user.save();
        res.json({ message: `Successfully upgraded to ${tier}`, user });
    } catch (error) {
        console.error("Upgrade Error:", error);
        res.status(500).json({ message: 'Server error' });
    }
});

// 10. อัปเดตชื่อผู้ใช้
app.put('/api/user/name', authenticateToken, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name || name.trim() === '') {
            return res.status(400).json({ message: 'Name cannot be empty' });
        }

        const user = await User.findById(req.user.id);
        user.name = name.trim();
        await user.save();

        res.json({ message: 'Name updated successfully', user });
    } catch (error) {
        console.error("Update Name Error:", error);
        res.status(500).json({ message: 'Server error' });
    }
});

// 8. สร้างหน้าต่างชำระเงิน (Stripe Checkout)
app.post('/api/payment/create-checkout', authenticateToken, async (req, res) => {
    try {
        const { tier } = req.body; 
        
        let price = 0;
        if (tier === 'ECO') price = 899; 
        else if (tier === 'PREMIUM') price = 1499; 

        const session = await stripe.checkout.sessions.create({
            line_items: [{
                price_data: {
                    currency: 'usd',
                    recurring: { interval: 'month' }, 
                    product_data: {
                        name: `PixelMe - ${tier} Plan`,
                        description: `Monthly subscription for ${tier} tier.`,
                    },
                    unit_amount: price,
                },
                quantity: 1,
            }],
            mode: 'subscription', 
            // 🟢 เพิ่ม &session_id={CHECKOUT_SESSION_ID} เพื่อให้หน้าเว็บรู้รหัสการสั่งซื้อ
            success_url: 'http://localhost:5500/pixelme/index.html?payment=success&tier=' + tier + '&session_id={CHECKOUT_SESSION_ID}',
            cancel_url: 'http://localhost:5500/pixelme/index.html',
            metadata: {
                userId: req.user.id,
                tier: tier
            }
        });

        res.json({ checkoutUrl: session.url });
    } catch (error) {
        console.error("Stripe Error:", error);
        res.status(500).json({ message: 'Payment gateway error' });
    }
});

// 9. หน้าจัดการสมาชิก (Stripe Customer Portal) สำหรับยกเลิกรายเดือน
app.post('/api/payment/create-portal', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        
        // เช็คว่าลูกค้าคนนี้มีรหัส Stripe หรือยัง (เคยจ่ายเงินหรือยัง)
        if (!user.stripeCustomerId) {
            return res.status(400).json({ message: 'No active subscription found.' });
        }

        // สร้างลิงก์ Portal ของลูกค้าคนนี้
        const session = await stripe.billingPortal.sessions.create({
            customer: user.stripeCustomerId,
            return_url: 'http://localhost:5500/pixelme/index.html', // 🟢 กลับมาหน้าเว็บเราหลังจัดการเสร็จ
        });

        res.json({ portalUrl: session.url });
    } catch (error) {
        console.error("Portal Error:", error);
        res.status(500).json({ message: 'Could not open billing portal' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));