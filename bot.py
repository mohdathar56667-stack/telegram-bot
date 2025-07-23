import os
import re
import csv
import asyncio
import bcrypt
from datetime import datetime
from dotenv import load_dotenv
from io import StringIO
from typing import Dict, List, Optional, Tuple

import asyncpg
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
    CallbackQueryHandler,
    ConversationHandler
)
import logging

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Conversation states
(EMAIL, PASSWORD, MAIN_MENU, APP_SELECTION, ACTIVATION_PROOF, 
 ADMIN_MODE, ADD_APP_MODE, EDIT_APP_MODE, TOGGLE_APP_MODE, 
 REPORT_MODE, DELETE_REPORT_MODE, DELETE_USER_MODE, ADD_USER) = range(13)

# Database connection pool
db_pool = None

# Status messages
STATUS_MESSAGES = {
    "approved": "✅ Approved",
    "rejected": "❌ Rejected",
    "pending": "⏳ Pending",
    "enabled": "🟢 Enabled",
    "disabled": "🔴 Disabled"
}

# Rejection reasons
REJECTION_REASONS = {
    "77": "Incorrect Proof - Video/screenshot is incorrect, send correct recording showing process",
    "78": "Improper Activation - Activation not done properly, send correct video",
    "79": "Fraud Detected - Fraud detected, account not showing",
    "80": "Wrong Device - Activation not done on user's device",
    "81": "Late Submission - Activation completed after deadline",
    "nt": "Non Trade Approved"
}

# Apps that require screenshots
SCREENSHOT_APPS = ['mstock', 'angelone']

async def init_db():
    """Initialize database connection pool"""
    global db_pool
    try:
        db_pool = await asyncpg.create_pool(
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME'),
            host=os.getenv('DB_HOST'),
            port=os.getenv('DB_PORT', '5432'),
            min_size=5,
            max_size=20
        )
        
        # Create tables if they don't exist
        async with db_pool.acquire() as conn:
            await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                name VARCHAR(255) NOT NULL,
                chat_id BIGINT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                is_admin BOOLEAN DEFAULT FALSE
            )
            ''')
            
            await conn.execute('''
            CREATE TABLE IF NOT EXISTS apps (
                id SERIAL PRIMARY KEY,
                name VARCHAR(50) UNIQUE NOT NULL,
                report_time VARCHAR(50) NOT NULL,
                report_updated VARCHAR(50) NOT NULL,
                status INTEGER DEFAULT 0,
                requires_screenshot BOOLEAN DEFAULT FALSE
            )
            ''')
            
            await conn.execute('''
            CREATE TABLE IF NOT EXISTS activations (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                app_id INTEGER REFERENCES apps(id),
                mobile VARCHAR(20) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                reason VARCHAR(50),
                message_id BIGINT,
                submission_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                UNIQUE(app_id, mobile)
            )
            ''')
            
            await conn.execute('''
            CREATE TABLE IF NOT EXISTS admin_logs (
                id SERIAL PRIMARY KEY,
                admin_id INTEGER REFERENCES users(id),
                action TEXT NOT NULL,
                details JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
            ''')
            
            # Insert default apps if they don't exist
            default_apps = [
                ("paytmmoney", "every 2 days", "16 July", False),
                ("angelone", "daily", "15 July", True),
                ("lemonn", "weekly", "14 July", False),
                ("mstock", "every 3 days", "13 July", True),
                ("upstox", "monthly", "12 July", False)
            ]
            
            for app in default_apps:
                await conn.execute('''
                INSERT INTO apps (name, report_time, report_updated, requires_screenshot)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (name) DO NOTHING
                ''', app[0], app[1], app[2], app[3])
                
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

async def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

async def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

async def get_user_by_email(email: str) -> Optional[Dict]:
    """Get user by email"""
    try:
        async with db_pool.acquire() as conn:
            return await conn.fetchrow(
                "SELECT * FROM users WHERE email = $1", 
                email.lower()
            )
    except Exception as e:
        logger.error(f"Error getting user by email: {e}")
        return None

async def add_user(email: str, password: str, name: str, chat_id: int = None) -> Tuple[bool, str]:
    """Add new user with hashed password"""
    try:
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return False, "Invalid email format"

        hashed_pw = await hash_password(password)
        async with db_pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO users (email, password_hash, name, chat_id)
                VALUES ($1, $2, $3, $4)""",
                email.lower(), hashed_pw, name, chat_id
            )
        return True, "User added successfully"
    except asyncpg.UniqueViolationError:
        return False, "User already exists"
    except Exception as e:
        logger.error(f"Error adding user: {e}")
        return False, "Failed to add user"

async def authenticate_user(email: str, password: str) -> Tuple[bool, Optional[Dict]]:
    """Authenticate user with email and password"""
    try:
        user = await get_user_by_email(email)
        if not user:
            return False, None
            
        if await verify_password(password, user['password_hash']):
            return True, user
        return False, None
    except Exception as e:
        logger.error(f"Error authenticating user: {e}")
        return False, None

async def update_user_chat_id(email: str, chat_id: int) -> bool:
    """Update user's chat_id"""
    try:
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET chat_id = $1 WHERE email = $2",
                chat_id, email.lower()
            )
        return True
    except Exception as e:
        logger.error(f"Error updating chat_id: {e}")
        return False

async def get_apps(include_disabled: bool = False) -> List[Dict]:
    """Get list of apps"""
    try:
        async with db_pool.acquire() as conn:
            if include_disabled:
                return await conn.fetch("SELECT * FROM apps ORDER BY name")
            return await conn.fetch(
                "SELECT * FROM apps WHERE status = 0 ORDER BY name"
            )
    except Exception as e:
        logger.error(f"Error getting apps: {e}")
        return []

async def get_app_by_name(name: str) -> Optional[Dict]:
    """Get app by name"""
    try:
        async with db_pool.acquire() as conn:
            return await conn.fetchrow(
                "SELECT * FROM apps WHERE name = $1",
                name.lower()
            )
    except Exception as e:
        logger.error(f"Error getting app by name: {e}")
        return None

async def add_app(name: str, report_time: str = "daily", report_updated: str = None) -> Tuple[bool, str]:
    """Add new app"""
    try:
        if not name or not re.match(r'^[a-z0-9]+$', name):
            return False, "Invalid app name (only lowercase letters and numbers allowed)"

        report_updated = report_updated or datetime.now().strftime('%d %B')
        async with db_pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO apps (name, report_time, report_updated)
                VALUES ($1, $2, $3)""",
                name.lower(), report_time, report_updated
            )
        return True, "App added successfully"
    except asyncpg.UniqueViolationError:
        return False, "App already exists"
    except Exception as e:
        logger.error(f"Error adding app: {e}")
        return False, "Failed to add app"

async def toggle_app_status(name: str) -> Tuple[bool, str]:
    """Toggle app status between enabled/disabled"""
    try:
        async with db_pool.acquire() as conn:
            app = await conn.fetchrow(
                "UPDATE apps SET status = 1 - status WHERE name = $1 RETURNING *",
                name.lower()
            )
            if not app:
                return False, "App not found"
                
            status = "disabled" if app['status'] == 1 else "enabled"
            return True, f"App {name} {status}"
    except Exception as e:
        logger.error(f"Error toggling app status: {e}")
        return False, "Failed to update app status"

async def update_app_report_time(name: str, report_time: str, report_updated: str) -> Tuple[bool, str]:
    """Update app's report time"""
    try:
        async with db_pool.acquire() as conn:
            await conn.execute(
                """UPDATE apps 
                SET report_time = $1, report_updated = $2 
                WHERE name = $3""",
                report_time, report_updated, name.lower()
            )
        return True, "App report time updated"
    except Exception as e:
        logger.error(f"Error updating app report time: {e}")
        return False, "Failed to update app"

async def delete_app(name: str) -> Tuple[bool, str]:
    """Delete an app"""
    try:
        async with db_pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM apps WHERE name = $1",
                name.lower()
            )
            if result == "DELETE 0":
                return False, "App not found"
        return True, "App deleted successfully"
    except Exception as e:
        logger.error(f"Error deleting app: {e}")
        return False, "Failed to delete app"

async def create_activation(user_id: int, app_id: int, mobile: str) -> Tuple[bool, str]:
    """Create new activation record"""
    try:
        # Clean mobile number
        mobile = re.sub(r'\D', '', mobile)
        if len(mobile) != 10:
            return False, "Mobile number must be 10 digits"
            
        async with db_pool.acquire() as conn:
            # Check for duplicate activation
            existing = await conn.fetchrow(
                """SELECT * FROM activations 
                WHERE app_id = $1 AND mobile = $2 
                AND status IN ('pending', 'approved')""",
                app_id, mobile
            )
            if existing:
                return False, "Duplicate activation for this mobile number"
                
            await conn.execute(
                """INSERT INTO activations (user_id, app_id, mobile)
                VALUES ($1, $2, $3)""",
                user_id, app_id, mobile
            )
        return True, "Activation submitted successfully"
    except Exception as e:
        logger.error(f"Error creating activation: {e}")
        return False, "Failed to record activation"

async def get_user_activations(user_id: int, limit: int = 50) -> List[Dict]:
    """Get user's activations"""
    try:
        async with db_pool.acquire() as conn:
            return await conn.fetch(
                """SELECT a.*, ap.name as app_name 
                FROM activations a
                JOIN apps ap ON a.app_id = ap.id
                WHERE a.user_id = $1
                ORDER BY a.submission_date DESC
                LIMIT $2""",
                user_id, limit
            )
    except Exception as e:
        logger.error(f"Error getting user activations: {e}")
        return []

async def update_activation_status(app_name: str, mobile: str, status: str, reason: str = None) -> Tuple[bool, str]:
    """Update activation status"""
    try:
        async with db_pool.acquire() as conn:
            result = await conn.execute(
                """UPDATE activations 
                SET status = $1, reason = $2
                FROM apps 
                WHERE activations.app_id = apps.id 
                AND apps.name = $3 
                AND activations.mobile = $4""",
                status, reason, app_name.lower(), mobile
            )
            if result == "UPDATE 0":
                return False, "Activation not found"
        return True, "Activation status updated"
    except Exception as e:
        logger.error(f"Error updating activation: {e}")
        return False, "Failed to update activation"

async def delete_activation(app_name: str, mobile: str) -> Tuple[bool, str]:
    """Delete activation record"""
    try:
        async with db_pool.acquire() as conn:
            result = await conn.execute(
                """DELETE FROM activations 
                USING apps 
                WHERE activations.app_id = apps.id 
                AND apps.name = $1 
                AND activations.mobile = $2""",
                app_name.lower(), mobile
            )
            if result == "DELETE 0":
                return False, "Activation not found"
        return True, "Activation deleted successfully"
    except Exception as e:
        logger.error(f"Error deleting activation: {e}")
        return False, "Failed to delete activation"

async def log_admin_action(admin_id: int, action: str, details: Dict = None):
    """Log admin actions for audit trail"""
    try:
        async with db_pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO admin_logs (admin_id, action, details)
                VALUES ($1, $2, $3)""",
                admin_id, action, details
            )
    except Exception as e:
        logger.error(f"Failed to log admin action: {e}")

async def generate_csv_report() -> Tuple[Optional[str], Optional[str]]:
    """Generate CSV reports for activations and users"""
    try:
        async with db_pool.acquire() as conn:
            # Activation report
            activations = await conn.fetch(
                """SELECT u.email, a.mobile, ap.name as app, 
                a.status, a.reason, a.submission_date
                FROM activations a
                JOIN users u ON a.user_id = u.id
                JOIN apps ap ON a.app_id = ap.id
                ORDER BY a.submission_date DESC
                LIMIT 10000"""
            )
            
            activation_output = StringIO()
            activation_writer = csv.writer(activation_output)
            activation_writer.writerow(["Email", "Mobile", "App", "Status", "Reason", "Submission Date"])
            
            for act in activations:
                activation_writer.writerow([
                    act['email'],
                    act['mobile'],
                    act['app'],
                    act['status'],
                    REJECTION_REASONS.get(act['reason'], act['reason']),
                    act['submission_date'].strftime('%Y-%m-%d %H:%M:%S') if act['submission_date'] else ''
                ])
            
            # User report
            users = await conn.fetch(
                """SELECT email, name, created_at 
                FROM users 
                ORDER BY created_at DESC
                LIMIT 10000"""
            )
            
            user_output = StringIO()
            user_writer = csv.writer(user_output)
            user_writer.writerow(["Email", "Name", "Created At"])
            
            for user in users:
                user_writer.writerow([
                    user['email'],
                    user['name'],
                    user['created_at'].strftime('%Y-%m-%d %H:%M:%S') if user['created_at'] else ''
                ])
            
            return activation_output.getvalue(), user_output.getvalue()
    except Exception as e:
        logger.error(f"Error generating CSV reports: {e}")
        return None, None

# Rate limiting decorator
def rate_limit(limit: int, per: int):
    """Decorator to limit how often a function can be called"""
    def decorator(func):
        last_called = {}
        
        async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE):
            user_id = update.effective_user.id
            now = datetime.now().timestamp()
            
            if user_id in last_called:
                elapsed = now - last_called[user_id]
                if elapsed < per:
                    await update.message.reply_text(
                        "⚠️ Please wait before sending another request."
                    )
                    return
            
            last_called[user_id] = now
            return await func(update, context)
        
        return wrapped
    
    return decorator

# Bot handlers
@rate_limit(limit=3, per=60)
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if str(update.effective_user.id) == os.getenv('ADMIN_CHAT_ID'):
        await update.message.reply_text(
            "👑 *Admin Mode*\n\n"
            "Use /adminmode to enter admin panel\n"
            "Use /cancel to exit any operation",
            parse_mode='Markdown'
        )
        return ConversationHandler.END

    email = context.user_data.get('email')
    if email:
        user = await get_user_by_email(email)
        if user:
            return await main_menu(update, context)

    context.user_data['chat_id'] = update.effective_chat.id
    await update.message.reply_text(
        "🌟 *Welcome to Earner Community Activation Bot!* 🌟\n\n"
        "Please enter your registered *email address*:",
        parse_mode='Markdown'
    )
    return EMAIL

async def email_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    email = update.message.text.strip().lower()
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        await update.message.reply_text("❌ Invalid email format. Please enter a valid email address:")
        return EMAIL
    context.user_data['email'] = email
    await update.message.reply_text("🔒 Please enter your *password*:", parse_mode='Markdown')
    return PASSWORD

async def password_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    password = update.message.text.strip()
    if len(password) < 6:
        await update.message.reply_text("❌ Password must be at least 6 characters. Please try again:")
        return PASSWORD

    email = context.user_data['email']
    authenticated, user = await authenticate_user(email, password)
    
    if authenticated and user:
        await update_user_chat_id(email, update.effective_chat.id)
        context.user_data['name'] = user['name']
        context.user_data['user_id'] = user['id']
        await update.message.reply_text("✅ *Login successful!* 🎉", parse_mode='Markdown')
        return await main_menu(update, context)
    else:
        await update.message.reply_text(
            "❌ *Invalid email or password.*\n\n"
            "Please enter your *email address* again:",
            parse_mode='Markdown'
        )
        return EMAIL

async def main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        if not context.user_data.get('email'):
            await update.message.reply_text("❌ Please /start to login first")
            return ConversationHandler.END

        if update.callback_query:
            await update.callback_query.answer()
            message_editor = update.callback_query.edit_message_text
        else:
            message_editor = update.message.reply_text

        name = context.user_data.get('name', 'User')
        email = context.user_data.get('email', '')

        keyboard = [
            [InlineKeyboardButton("📊 My Activation Status", callback_data='status')],
            [InlineKeyboardButton("📤 Send Activation Proof", callback_data='proof')],
            [InlineKeyboardButton("📖 How To Work Guide", callback_data='guide')],
            [InlineKeyboardButton("📜 Activation Rules", callback_data='rules')],
            [InlineKeyboardButton("⏰ Report Timing", callback_data='report_timing')],
        ]

        await message_editor(
            f"👋 *Hello {name}!* ({email})\n\n"
            "🔹 *Activation Dashboard* - Please select an option:",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return MAIN_MENU
    except Exception as e:
        logger.error(f"Error in main_menu: {e}")
        await handle_error(update, context)
        return ConversationHandler.END

async def activation_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Show activation status"""
    try:
        query = update.callback_query
        await query.answer()

        user_id = context.user_data.get('user_id')
        if not user_id:
            await query.edit_message_text("❌ Session expired. Please /start again.")
            return ConversationHandler.END

        activations = await get_user_activations(user_id)
        
        if activations:
            text = "📊 *Your Activation Status:*\n\n"
            for act in activations:
                status = act.get('status', '').lower()
                reason = REJECTION_REASONS.get(act.get('reason', ''), act.get('reason', ''))
                
                status_emoji = "✅" if status == "approved" else "❌" if status == "rejected" else "⏳"
                status_display = status.capitalize()
                
                text += (
                    f"{status_emoji} *{act.get('app_name', '').upper()}*\n"
                    f"📱 *Mobile:* `{act.get('mobile', '')}`\n"
                    f"🔄 *Status:* {status_display}\n"
                    f"📝 *Reason:* {reason}\n"
                    f"📅 *Date:* {act.get('submission_date', '').strftime('%Y-%m-%d') if act.get('submission_date') else 'N/A'}\n\n"
                )
        else:
            text = "ℹ️ No activations found. Submit your first activation proof!"

        await query.edit_message_text(
            text,
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data='back')]
            ])
        )
        return MAIN_MENU
    except Exception as e:
        logger.error(f"Error in activation_status: {e}")
        await query.edit_message_text(
            "❌ Error loading your status. Please try again.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data='back')]
            ])
        )
        return MAIN_MENU

async def send_activation_proof(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        query = update.callback_query
        await query.answer()

        if query.data == 'same_app':
            app = context.user_data.get('selected_app')
            if not app:
                return await main_menu(update, context)
            media_type = "screenshot/video" if app in SCREENSHOT_APPS else "video"
            await query.edit_message_text(
                f"📤 *Send proof for {app.upper()}*\n\n"
                f"Please send {media_type} with mobile number in caption\n"
                f"Example: `9876543210` (10 digits only, no spaces)",
                parse_mode='Markdown'
            )
            return ACTIVATION_PROOF

        apps = await get_apps()
        if not apps:
            await query.edit_message_text(
                "⚠️ No apps available for activation.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Back", callback_data='back')]
                ])
            )
            return MAIN_MENU

        keyboard = [
            [InlineKeyboardButton(app['name'].upper(), callback_data=f"app_{app['name']}")]
            for app in apps
        ]
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data='back')])

        await query.edit_message_text(
            "📲 *Select application for activation:*",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return APP_SELECTION
    except Exception as e:
        logger.error(f"Error in send_activation_proof: {e}")
        await handle_error(update, context)
        return MAIN_MENU

async def app_selected(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        query = update.callback_query
        await query.answer()
        
        app_name = query.data.replace('app_', '')
        context.user_data['selected_app'] = app_name
        
        media_type = "screenshot/video" if app_name in SCREENSHOT_APPS else "video"
        await query.edit_message_text(
            f"📤 *Send proof for {app_name.upper()}*\n\n"
            f"Please send {media_type} with mobile number in caption\n"
            f"Example: `9876543210` (10 digits only, no spaces)",
            parse_mode='Markdown'
        )
        return ACTIVATION_PROOF
    except Exception as e:
        logger.error(f"Error in app_selected: {e}")
        await handle_error(update, context)
        return MAIN_MENU

async def process_activation_proof(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Process submitted activation proof"""
    try:
        app_name = context.user_data.get('selected_app')
        if not app_name:
            await update.message.reply_text("❌ No app selected. Please start over.")
            return MAIN_MENU

        # Validate media type
        app = await get_app_by_name(app_name)
        if not app:
            await update.message.reply_text("❌ Invalid app selected")
            return MAIN_MENU

        if app['requires_screenshot']:
            if not (update.message.photo or update.message.video):
                await update.message.reply_text(f"❌ Please send a screenshot or video for {app_name.upper()}")
                return ACTIVATION_PROOF
        elif not update.message.video:
            await update.message.reply_text(f"❌ Please send a video for {app_name.upper()}")
            return ACTIVATION_PROOF

        # Validate mobile number
        if not update.message.caption:
            await update.message.reply_text("❌ Please include mobile number in caption")
            return ACTIVATION_PROOF

        mobile = update.message.caption.strip()
        if not re.fullmatch(r'\d{10}', mobile):
            await update.message.reply_text(
                "❌ *Invalid mobile number*\n\n"
                "Must be 10 digits without spaces.\n"
                "Example: `9876543210`",
                parse_mode='Markdown'
            )
            return ACTIVATION_PROOF

        user_id = context.user_data.get('user_id')
        if not user_id:
            await update.message.reply_text("❌ Session expired. Please /start again.")
            return ConversationHandler.END

        # Record activation
        success, message = await create_activation(user_id, app['id'], mobile)
        if not success:
            await update.message.reply_text(f"❌ {message}")
            return MAIN_MENU

        # Forward to channel with approval buttons
        channel_id = os.getenv('CHANNEL_ID')
        if channel_id:
            try:
                # Prepare caption
                user_email = context.user_data.get('email')
                caption = (
                    f"📬 *New Activation Request*\n\n"
                    f"📲 *App:* {app_name.upper()}\n"
                    f"📧 *User:* `{user_email}`\n"
                    f"📱 *Mobile:* `{mobile}`\n\n"
                    f"🔄 *Status:* ⏳ Pending"
                )

                # Prepare approval/rejection buttons
                keyboard = [
                    [
                        InlineKeyboardButton("✅ Approve", callback_data=f"approve_{user_email}_{app_name}_{mobile}"),
                        InlineKeyboardButton("❌ Reject", callback_data=f"reject_{user_email}_{app_name}_{mobile}")
                    ]
                ]

                # Add rejection reasons
                rejection_reasons = [
                    ["❌ Incorrect Proof (77)", f"reason_77_{user_email}_{app_name}_{mobile}"],
                    ["❌ Improper Activation (78)", f"reason_78_{user_email}_{app_name}_{mobile}"],
                    ["❌ Fraud Detected (79)", f"reason_79_{user_email}_{app_name}_{mobile}"],
                    ["❌ Wrong Device (80)", f"reason_80_{user_email}_{app_name}_{mobile}"],
                    ["❌ Late Submission (81)", f"reason_81_{user_email}_{app_name}_{mobile}"]
                ]

                if app_name == 'angelone':
                    keyboard.append([InlineKeyboardButton("✅ Non Trade Approved", callback_data=f"reason_nt_{user_email}_{app_name}_{mobile}")])

                for reason in rejection_reasons:
                    keyboard.append([InlineKeyboardButton(reason[0], callback_data=reason[1])])

                # Send to channel based on media type
                if update.message.video:
                    message = await context.bot.send_video(
                        chat_id=channel_id,
                        video=update.message.video.file_id,
                        caption=caption,
                        parse_mode='Markdown',
                        reply_markup=InlineKeyboardMarkup(keyboard)
                    )
                elif update.message.photo:
                    message = await context.bot.send_photo(
                        chat_id=channel_id,
                        photo=update.message.photo[-1].file_id,  # Highest resolution
                        caption=caption,
                        parse_mode='Markdown',
                        reply_markup=InlineKeyboardMarkup(keyboard)
                    )

                # Store message_id in database
                async with db_pool.acquire() as conn:
                    await conn.execute(
                        """UPDATE activations 
                        SET message_id = $1
                        WHERE user_id = $2 AND app_id = $3 AND mobile = $4""",
                        message.message_id, user_id, app['id'], mobile
                    )

            except Exception as e:
                logger.error(f"Failed to forward to channel: {e}")
                admin_id = os.getenv('ADMIN_CHAT_ID')
                if admin_id:
                    await context.bot.send_message(
                        chat_id=admin_id,
                        text=f"❌ Failed to forward activation:\n\nApp: {app_name}\nUser: {user_email}\nError: {e}"
                    )

        # Success response to user
        keyboard = [
            [InlineKeyboardButton("📤 Send Another (Same App)", callback_data='same_app')],
            [InlineKeyboardButton("📲 Select Another App", callback_data='proof')],
            [InlineKeyboardButton("🏠 Main Menu", callback_data='back')]
        ]

        await update.message.reply_text(
            "✅ *Activation submitted successfully!*\n\n"
            "You can check your status in the main menu.",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return MAIN_MENU

    except Exception as e:
        logger.error(f"Error in process_activation_proof: {e}")
        await update.message.reply_text(
            "❌ *An error occurred*\n\n"
            "Please try again or contact support if the problem persists.",
            parse_mode='Markdown'
        )
        return MAIN_MENU

async def show_guide(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        query = update.callback_query
        await query.answer()

        await query.edit_message_text(
            "*📖 How To Work Guide*\n\n"
            "1. Select an app from the menu\n"
            "2. Follow the app-specific activation instructions\n"
            "3. Record a video/screenshot as proof\n"
            "4. Submit with your mobile number in caption\n"
            "5. Wait for admin approval\n\n"
            "For specific app guides, contact support.",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data='back')]
            ])
        )
        return MAIN_MENU
    except Exception as e:
        logger.error(f"Error in show_guide: {e}")
        await handle_error(update, context)
        return MAIN_MENU

async def show_rules(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        query = update.callback_query
        await query.answer()

        await query.edit_message_text(
            "*📜 Activation Rules*\n\n"
            "1. Only one activation per mobile number per app\n"
            "2. Submissions must be genuine and verifiable\n"
            "3. Fraudulent submissions will be banned\n"
            "4. Follow all app-specific requirements\n"
            "5. Admin decisions are final\n\n"
            "Violations may result in account suspension.",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data='back')]
            ])
        )
        return MAIN_MENU
    except Exception as e:
        logger.error(f"Error in show_rules: {e}")
        await handle_error(update, context)
        return MAIN_MENU

async def show_report_timing(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        query = update.callback_query
        await query.answer()

        apps = await get_apps(include_disabled=True)
        
        text = "⏰ *Report Timing Information*\n\n"
        
        for app in apps:
            status = f" ({STATUS_MESSAGES['enabled' if app.get('status', 0) == 0 else 'disabled']})"
            
            text += (
                f"📱 *{app.get('name', '').upper()}*{status}\n"
                f"⏰ *Report Time:* {app.get('report_time', 'N/A')}\n"
                f"🔄 *Last Updated:* {app.get('report_updated', 'N/A')}\n\n"
            )

        await query.edit_message_text(
            text,
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data='back')]
            ])
        )
        return MAIN_MENU
    except Exception as e:
        logger.error(f"Error in show_report_timing: {e}")
        await handle_error(update, context)
        return MAIN_MENU

async def back_to_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    return await main_menu(update, context)

async def admin_mode_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_user.id) != os.getenv('ADMIN_CHAT_ID'):
        await update.message.reply_text("❌ This command is for admin only.")
        return ConversationHandler.END

    context.user_data['admin_mode'] = True
    
    keyboard = [
        [InlineKeyboardButton("📝 Edit Reports", callback_data='edit_reports')],
        [InlineKeyboardButton("📲 Manage Apps", callback_data='manage_apps')],
        [InlineKeyboardButton("👤 Manage Users", callback_data='manage_users')],
        [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
    ]

    await update.message.reply_text(
        "🛠 *Admin Mode Activated*\n\n"
        "Select an option from the menu below:",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return ADMIN_MODE

async def admin_mode_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if str(query.from_user.id) != os.getenv('ADMIN_CHAT_ID'):
        await query.edit_message_text("❌ Unauthorized access.")
        return ConversationHandler.END

    try:
        if query.data == 'manage_apps':
            keyboard = [
                [InlineKeyboardButton("⏰ Edit Report Time", callback_data='edit_app_time')],
                [InlineKeyboardButton("🔄 Toggle App Status", callback_data='toggle_app')],
                [InlineKeyboardButton("❌ Delete App", callback_data='delete_app')],
                [InlineKeyboardButton("📲 Add New App", callback_data='add_app')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ]
            await query.edit_message_text(
                "📲 *Manage Apps*\n\n"
                "Select an option:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data == 'edit_app_time':
            apps = await get_apps(include_disabled=True)
            keyboard = [
                [InlineKeyboardButton(app['name'].upper(), callback_data=f"edittime_{app['name']}")]
                for app in apps
            ]
            keyboard.append([InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')])

            await query.edit_message_text(
                "⏰ *Edit App Report Time*\n\n"
                "Select app to edit:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data.startswith('edittime_'):
            app_name = query.data.replace('edittime_', '')
            context.user_data['edit_app'] = app_name
            await query.edit_message_text(
                f"⏰ *Editing Report Time for {app_name.upper()}*\n\n"
                "Please send the new report time and updated date in format:\n\n"
                "`report_time`\n"
                "`report_updated`\n\n"
                "Example:\n"
                "`every 2 days`\n"
                "`16 July`",
                parse_mode='Markdown'
            )
            return EDIT_APP_MODE
            
        elif query.data == 'toggle_app':
            apps = await get_apps(include_disabled=True)
            keyboard = []
            
            for app in apps:
                current_status = app.get('status', 0)
                action = "Disable" if current_status == 0 else "Enable"
                status_emoji = "🟢" if current_status == 0 else "🔴"
                keyboard.append([
                    InlineKeyboardButton(
                        f"{status_emoji} {app['name'].upper()} - {action}", 
                        callback_data=f"toggle_{app['name']}"
                    )
                ])
            
            keyboard.append([InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')])

            await query.edit_message_text(
                "🔄 *Toggle App Status*\n\n"
                "Select app to enable/disable:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data.startswith('toggle_'):
            app_name = query.data.replace('toggle_', '')
            success, message = await toggle_app_status(app_name)
            
            await query.edit_message_text(
                f"✅ {message}",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Back to Apps", callback_data='manage_apps')],
                    [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
                ])
            )
            return ADMIN_MODE
            
        elif query.data == 'delete_app':
            apps = await get_apps(include_disabled=True)
            keyboard = [
                [InlineKeyboardButton(app['name'].upper(), callback_data=f"delapp_{app['name']}")]
                for app in apps
            ]
            keyboard.append([InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')])

            await query.edit_message_text(
                "❌ *Delete App*\n\n"
                "Select app to delete:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data.startswith('delapp_'):
            app_name = query.data.replace('delapp_', '')
            success, message = await delete_app(app_name)
            await query.edit_message_text(
                f"{'✅' if success else '❌'} {message}",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Back to Apps", callback_data='manage_apps')],
                    [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
                ])
            )
            return ADMIN_MODE
            
        elif query.data == 'add_app':
            await query.edit_message_text(
                "📲 *Add New App*\n\n"
                "Please send the app name to add (lowercase, no spaces):\n\n"
                "Example: `newapp`",
                parse_mode='Markdown'
            )
            return ADD_APP_MODE
            
        elif query.data == 'manage_users':
            keyboard = [
                [InlineKeyboardButton("👤 Add User", callback_data='add_user')],
                [InlineKeyboardButton("❌ Delete User", callback_data='delete_user_prompt')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ]
            await query.edit_message_text(
                "👤 *Manage Users*\n\n"
                "Select an option:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data == 'add_user':
            await query.edit_message_text(
                "👤 *Add New User*\n\n"
                "Send user details in format:\n\n"
                "`email`\n"
                "`password`\n"
                "`name`\n\n"
                "For bulk add, separate users with blank lines:\n\n"
                "`email1`\n`password1`\n`name1`\n\n"
                "`email2`\n`password2`\n`name2`",
                parse_mode='Markdown'
            )
            return ADD_USER
            
        elif query.data == 'delete_user_prompt':
            await query.edit_message_text(
                "🗑 *Delete User Mode*\n\n"
                "Please send user credentials in format:\n\n"
                "`email@example.com`\n"
                "`password`\n\n"
                "For bulk delete, separate users with blank lines:\n\n"
                "`email1@example.com`\n`password1`\n\n"
                "`email2@example.com`\n`password2`\n\n"
                "Type /cancel to exit",
                parse_mode='Markdown'
            )
            return DELETE_USER_MODE
            
        elif query.data == 'edit_reports':
            keyboard = [
                [InlineKeyboardButton("📄 Download CSV", callback_data='download_csv')],
                [InlineKeyboardButton("📊 Download JSON", callback_data='download_json')],
                [InlineKeyboardButton("🗑 Delete Reports", callback_data='delete_reports')],
                [InlineKeyboardButton("🔄 Update Reports", callback_data='report_mode')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ]
            await query.edit_message_text(
                "📝 *Manage Reports*\n\n"
                "Select an option:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data == 'report_mode':
            await query.edit_message_text(
                "📝 *Report Update Mode*\n\n"
                "Send updates in format:\n\n"
                "`app_name`\n"
                "`mobile_number`\n"
                "`status` (approved/rejected)\n"
                "`reason` (optional)\n\n"
                "Multiple updates separated by blank lines.",
                parse_mode='Markdown'
            )
            return REPORT_MODE
            
        elif query.data == 'delete_reports':
            await query.edit_message_text(
                "🗑 *Delete Reports*\n\n"
                "Send deletions in format:\n\n"
                "`app_name`\n"
                "`mobile_number`\n\n"
                "Multiple deletions separated by blank lines.",
                parse_mode='Markdown'
            )
            return DELETE_REPORT_MODE
            
        elif query.data == 'download_json':
            await send_json_command(update, context)
            return ADMIN_MODE
            
        elif query.data == 'download_csv':
            await send_csv_command(update, context)
            return ADMIN_MODE
            
        elif query.data == 'cancel_admin':
            context.user_data.pop('admin_mode', None)
            await query.edit_message_text(
                "🚫 *Admin mode deactivated*",
                parse_mode='Markdown'
            )
            return ConversationHandler.END
            
    except Exception as e:
        logger.error(f"Error in admin_mode_handler: {e}")
        await handle_error(update, context)
        return ADMIN_MODE

async def edit_app_time_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        text = update.message.text.strip()
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        if len(lines) < 2:
            await update.message.reply_text(
                "❌ Invalid format. Please send:\n\n"
                "`report_time`\n"
                "`report_updated`",
                parse_mode='Markdown'
            )
            return EDIT_APP_MODE

        report_time = lines[0]
        report_updated = lines[1]
        app_name = context.user_data.get('edit_app')
        
        success, message = await update_app_report_time(app_name, report_time, report_updated)
        await update.message.reply_text(
            f"{'✅' if success else '❌'} {message}",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back to Apps", callback_data='manage_apps')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ])
        )
        return ADMIN_MODE
    except Exception as e:
        logger.error(f"Error in edit_app_time_handler: {e}")
        await handle_error(update, context)
        return ADMIN_MODE

async def add_app_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        app_name = update.message.text.strip().lower()
        success, message = await add_app(app_name)
        await update.message.reply_text(
            f"{'✅' if success else '❌'} {message}",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back to Apps", callback_data='manage_apps')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ])
        )
        return ADMIN_MODE
    except Exception as e:
        logger.error(f"Error in add_app_handler: {e}")
        await handle_error(update, context)
        return ADMIN_MODE

async def report_mode_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle report updates with proper validation"""
    try:
        text = update.message.text.strip()
        if not text:
            await update.message.reply_text("Please provide valid update data")
            return REPORT_MODE

        entries = [entry for entry in text.split('\n\n') if entry.strip()][:50]
        results = []

        for entry in entries:
            lines = [line.strip() for line in entry.split('\n') if line.strip()]
            if len(lines) < 3:
                results.append(f"❌ Invalid format: {entry[:30]}...")
                continue

            app = lines[0].lower()
            mobile = lines[1]
            status = lines[2].lower()
            reason = lines[3] if len(lines) > 3 else None

            if status not in ['approved', 'rejected']:
                results.append(f"❌ Invalid status '{status}' for {app} - {mobile}")
                continue

            success, message = await update_activation_status(app, mobile, status, reason)
            results.append(f"{'✅' if success else '❌'} {message}")

        await update.message.reply_text("\n".join(results), parse_mode='Markdown')
        await update.message.reply_text(
            "Send more updates or /cancel to exit report mode."
        )
        return REPORT_MODE
    except Exception as e:
        logger.error(f"Error in report_mode_handler: {e}")
        await update.message.reply_text(
            "❌ Error processing updates. Please check format and try again.",
            parse_mode='Markdown'
        )
        return REPORT_MODE

async def delete_report_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        text = update.message.text.strip()
        if not text:
            await update.message.reply_text("Please provide valid deletion data")
            return DELETE_REPORT_MODE

        entries = [entry for entry in text.split('\n\n') if entry.strip()][:50]
        results = []

        for entry in entries:
            lines = [line.strip() for line in entry.split('\n') if line.strip()]
            if len(lines) < 2:
                results.append(f"❌ Invalid format: {entry[:30]}...")
                continue

            app = lines[0].lower()
            mobile = lines[1]

            deleted, message = await delete_activation(app, mobile)
            results.append(f"{'✅' if deleted else '❌'} {message}")

        await update.message.reply_text("\n".join(results), parse_mode='Markdown')
        await update.message.reply_text(
            "Send more deletions or /cancel to exit delete mode."
        )
        return DELETE_REPORT_MODE
    except Exception as e:
        logger.error(f"Error in delete_report_handler: {e}")
        await handle_error(update, context)
        return DELETE_REPORT_MODE

async def delete_user_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle user deletion with email/password input"""
    try:
        text = update.message.text.strip()
        if not text:
            await update.message.reply_text("Please provide valid user credentials")
            return DELETE_USER_MODE

        user_entries = [entry for entry in text.split('\n\n') if entry.strip()]
        results = []

        for entry in user_entries:
            lines = [line.strip() for line in entry.split('\n') if line.strip()]
            if len(lines) < 2:
                results.append(f"❌ Invalid format: {entry[:30]}...")
                continue

            email = lines[0].lower()
            password = lines[1]

            # Perform deletion
            async with db_pool.acquire() as conn:
                # First verify credentials
                user = await conn.fetchrow(
                    "SELECT * FROM users WHERE email = $1",
                    email
                )
                if not user or not await verify_password(password, user['password_hash']):
                    results.append(f"❌ User not found or wrong password: {email}")
                    continue
                
                # Then delete
                result = await conn.execute(
                    "DELETE FROM users WHERE email = $1 AND password_hash = $2",
                    email, user['password_hash']
                )
                if result == "DELETE 1":
                    results.append(f"✅ Deleted user: {email}")
                else:
                    results.append(f"❌ Failed to delete user: {email}")

        # Prepare response
        response = "🗑 *Deletion Results*\n\n" + "\n".join(results)
        
        # Show admin menu again after completion
        keyboard = [
            [InlineKeyboardButton("👤 Manage Users", callback_data='manage_users')],
            [InlineKeyboardButton("📝 Manage Reports", callback_data='edit_reports')],
            [InlineKeyboardButton("📲 Manage Apps", callback_data='manage_apps')],
            [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
        ]

        await update.message.reply_text(
            response,
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return ADMIN_MODE

    except Exception as e:
        logger.error(f"Error in delete_user_handler: {e}")
        await update.message.reply_text(
            "❌ Error processing deletion. Please try again.",
            parse_mode='Markdown'
        )
        return DELETE_USER_MODE

async def add_user_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        text = update.message.text.strip()
        if not text:
            await update.message.reply_text("Please provide valid user details")
            return ADD_USER

        user_entries = [entry for entry in text.split('\n\n') if entry.strip()][:20]
        results = []

        for entry in user_entries:
            parts = [p.strip() for p in entry.split('\n') if p.strip()]
            if len(parts) < 3:
                results.append(f"❌ Invalid format: {entry[:30]}...")
                continue

            email, password, name = parts[0], parts[1], ' '.join(parts[2:])
            success, message = await add_user(email, password, name)
            results.append(f"{'✅' if success else '❌'} {message}: `{email}`")

        await update.message.reply_text("\n".join(results), parse_mode='Markdown')
        await update.message.reply_text(
            "Send more user details or /cancel to exit admin mode."
        )
        return ADD_USER
    except Exception as e:
        logger.error(f"Error in add_user_handler: {e}")
        await handle_error(update, context)
        return ADD_USER

async def send_json_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if str(update.effective_user.id) != os.getenv('ADMIN_CHAT_ID'):
            await update.message.reply_text("❌ This command is for admin only.")
            return

        # Get data from database
        async with db_pool.acquire() as conn:
            users = await conn.fetch("SELECT * FROM users")
            activations = await conn.fetch(
                """SELECT a.*, u.email, ap.name as app_name 
                FROM activations a
                JOIN users u ON a.user_id = u.id
                JOIN apps ap ON a.app_id = ap.id"""
            )
            apps = await conn.fetch("SELECT * FROM apps")

        # Convert to JSON strings
        import json
        from io import BytesIO

        users_json = json.dumps([dict(user) for user in users], indent=2)
        activations_json = json.dumps([dict(act) for act in activations], indent=2)
        apps_json = json.dumps([dict(app) for app in apps], indent=2)

        # Send files
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=BytesIO(users_json.encode()),
            filename='users.json',
            caption='Users data'
        )

        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=BytesIO(activations_json.encode()),
            filename='activations.json',
            caption='Activations data'
        )

        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=BytesIO(apps_json.encode()),
            filename='apps.json',
            caption='Apps data'
        )

    except Exception as e:
        logger.error(f"Error in send_json_command: {e}")
        await update.message.reply_text("❌ Failed to send JSON files. Check logs for details.")

async def send_csv_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if str(update.effective_user.id) != os.getenv('ADMIN_CHAT_ID'):
            await update.message.reply_text("❌ This command is for admin only.")
            return

        activation_csv, user_csv = await generate_csv_report()
        if not activation_csv or not user_csv:
            await update.message.reply_text("❌ No data available to generate CSV reports.")
            return

        from io import BytesIO

        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=BytesIO(activation_csv.encode()),
            filename=f'activations_report_{datetime.now().strftime("%Y%m%d")}.csv',
            caption='Activations report (CSV)'
        )

        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=BytesIO(user_csv.encode()),
            filename=f'users_report_{datetime.now().strftime("%Y%m%d")}.csv',
            caption='Users report (CSV)'
        )

    except Exception as e:
        logger.error(f"Error in send_csv_command: {e}")
        await update.message.reply_text("❌ Failed to generate CSV reports. Check logs for details.")

async def admin_approve(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle approval from admin"""
    try:
        query = update.callback_query
        await query.answer()

        _, email, app, mobile = query.data.split('_')
        
        # Update activation status
        success, message = await update_activation_status(app, mobile, "approved")
        if not success:
            await query.answer(message, show_alert=True)
            return
        
        # Update channel message
        channel_id = os.getenv('CHANNEL_ID')
        if channel_id:
            async with db_pool.acquire() as conn:
                activation = await conn.fetchrow(
                    """SELECT a.*, ap.name as app_name 
                    FROM activations a
                    JOIN apps ap ON a.app_id = ap.id
                    JOIN users u ON a.user_id = u.id
                    WHERE u.email = $1 AND ap.name = $2 AND a.mobile = $3""",
                    email, app, mobile
                )
                
                if activation and activation.get('message_id'):
                    try:
                        await context.bot.edit_message_caption(
                            chat_id=channel_id,
                            message_id=activation['message_id'],
                            caption=(
                                f"✅ *Approved Activation*\n\n"
                                f"📲 *App:* {app.upper()}\n"
                                f"📧 *User:* `{email}`\n"
                                f"📱 *Mobile:* `{mobile}`\n\n"
                                f"🔄 *Status:* ✅ Approved"
                            ),
                            parse_mode='Markdown'
                        )
                    except Exception as e:
                        logger.error(f"Failed to edit channel message: {e}")

        await query.edit_message_text(
            text=f"✅ Approved activation for {app.upper()} ({mobile})",
            parse_mode='Markdown'
        )

    except Exception as e:
        logger.error(f"Error in admin_approve: {e}")
        await query.answer("Failed to process approval", show_alert=True)

async def admin_reject(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle rejection from admin"""
    try:
        query = update.callback_query
        await query.answer()

        _, email, app, mobile = query.data.split('_')

        # Prepare rejection reasons
        rejection_reasons = [
            ["❌ Incorrect Proof (77)", f"reason_77_{email}_{app}_{mobile}"],
            ["❌ Improper Activation (78)", f"reason_78_{email}_{app}_{mobile}"],
            ["❌ Fraud Detected (79)", f"reason_79_{email}_{app}_{mobile}"],
            ["❌ Wrong Device (80)", f"reason_80_{email}_{app}_{mobile}"],
            ["❌ Late Submission (81)", f"reason_81_{email}_{app}_{mobile}"]
        ]

        keyboard = []
        for reason in rejection_reasons:
            keyboard.append([InlineKeyboardButton(reason[0], callback_data=reason[1])])

        if app == 'angelone':
            keyboard.append([InlineKeyboardButton("✅ Non Trade Approved", callback_data=f"reason_nt_{email}_{app}_{mobile}")])

        await query.edit_message_text(
            text=f"Select rejection reason for {app.upper()}:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

    except Exception as e:
        logger.error(f"Error in admin_reject: {e}")
        await query.answer("Failed to process rejection", show_alert=True)

async def process_rejection(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Process specific rejection reason"""
    try:
        query = update.callback_query
        await query.answer()

        parts = query.data.split('_')
        reason_id = parts[1]
        email = parts[2]
        app = parts[3]
        mobile = parts[4]

        reason_text = REJECTION_REASONS.get(reason_id, "Unknown reason")

        # Special case for Non Trade Approved
        if reason_id == 'nt':
            status = "approved"
            status_text = "Approved with Note"
            status_emoji = "✅"
        else:
            status = "rejected"
            status_text = "Rejected"
            status_emoji = "❌"

        # Update activation
        success, message = await update_activation_status(app, mobile, status, reason_id)
        if not success:
            await query.answer(message, show_alert=True)
            return

        # Update channel message
        channel_id = os.getenv('CHANNEL_ID')
        if channel_id:
            async with db_pool.acquire() as conn:
                activation = await conn.fetchrow(
                    """SELECT a.*, ap.name as app_name 
                    FROM activations a
                    JOIN apps ap ON a.app_id = ap.id
                    JOIN users u ON a.user_id = u.id
                    WHERE u.email = $1 AND ap.name = $2 AND a.mobile = $3""",
                    email, app, mobile
                )
                
                if activation and activation.get('message_id'):
                    try:
                        await context.bot.edit_message_caption(
                            chat_id=channel_id,
                            message_id=activation['message_id'],
                            caption=(
                                f"{status_emoji} *{status_text} Activation*\n\n"
                                f"📲 *App:* {app.upper()}\n"
                                f"📧 *User:* `{email}`\n"
                                f"📱 *Mobile:* `{mobile}`\n\n"
                                f"🔄 *Status:* {status_emoji} {status_text}\n"
                                f"📝 *Reason:* {reason_text}"
                            ),
                            parse_mode='Markdown'
                        )
                    except Exception as e:
                        logger.error(f"Failed to edit channel message: {e}")

        await query.edit_message_text(
            text=(
                f"{status_emoji} *Activation {status_text}*\n\n"
                f"📲 *App:* {app.upper()}\n"
                f"📧 *User:* `{email}`\n"
                f"📱 *Mobile:* `{mobile}`\n\n"
                f"📝 *Reason:* {reason_text}"
            ),
            parse_mode='Markdown'
        )

    except Exception as e:
        logger.error(f"Error in process_rejection: {e}")
        await query.answer("Failed to process rejection reason", show_alert=True)

async def handle_error(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if update and update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.edit_message_text(
                "❌ An error occurred. Please try again.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🏠 Main Menu", callback_data='back')]
                ])
            )
        elif update and update.message:
            await update.message.reply_text(
                "❌ An error occurred. Please try again.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🏠 Main Menu", callback_data='back')]
                ])
            )
    except Exception as e:
        logger.error(f"Error in handle_error: {e}")

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    await update.message.reply_text('Operation cancelled.')
    return ConversationHandler.END

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "ℹ️ *Help*\n\n"
        "Use /start to begin\n"
        "Use /menu to return to main menu\n"
        "Use /cancel to cancel current operation",
        parse_mode='Markdown'
    )

async def error(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error(f"Update {update} caused error {context.error}")
    try:
        if update and update.callback_query:
            await update.callback_query.answer("An error occurred. Please try again.")
        elif update and update.message:
            await update.message.reply_text("An error occurred. Please try again.")
    except Exception as e:
        logger.error(f"Error in error handler: {e}")

async def main() -> None:
    # Initialize database connection
    await init_db()
    
    # Create default admin user if not exists
    admin_email = os.getenv('ADMIN_EMAIL')
    admin_password = os.getenv('ADMIN_PASSWORD')
    if admin_email and admin_password:
        admin_user = await get_user_by_email(admin_email)
        if not admin_user:
            success, message = await add_user(
                email=admin_email,
                password=admin_password,
                name="Admin",
                chat_id=int(os.getenv('ADMIN_CHAT_ID'))
            )
            if success:
                async with db_pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE users SET is_admin = TRUE WHERE email = $1",
                        admin_email.lower()
                    )
                logger.info("Admin user created successfully")
            else:
                logger.error(f"Failed to create admin user: {message}")

    # Start the bot
    application = Application.builder().token(os.getenv('TELEGRAM_TOKEN')).build()
    
    # Admin conversation handler
    admin_conv_handler = ConversationHandler(
        entry_points=[CommandHandler('adminmode', admin_mode_command)],
        states={
            ADMIN_MODE: [CallbackQueryHandler(admin_mode_handler)],
            ADD_APP_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, add_app_handler)],
            EDIT_APP_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, edit_app_time_handler)],
            REPORT_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, report_mode_handler)],
            DELETE_REPORT_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, delete_report_handler)],
            ADD_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, add_user_handler)],
            DELETE_USER_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, delete_user_handler)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
        per_message=False,
        per_chat=True,
        per_user=True,
    )

    # Main conversation handler
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            EMAIL: [MessageHandler(filters.TEXT & ~filters.COMMAND, email_input)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, password_input)],
            MAIN_MENU: [
                CallbackQueryHandler(activation_status, pattern='^status$'),
                CallbackQueryHandler(send_activation_proof, pattern='^proof$'),
                CallbackQueryHandler(show_guide, pattern='^guide$'),
                CallbackQueryHandler(show_rules, pattern='^rules$'),
                CallbackQueryHandler(show_report_timing, pattern='^report_timing$'),
                CallbackQueryHandler(back_to_menu, pattern='^back$'),
                CallbackQueryHandler(send_activation_proof, pattern='^same_app$'),
            ],
            APP_SELECTION: [
                CallbackQueryHandler(app_selected, pattern='^app_'),
                CallbackQueryHandler(back_to_menu, pattern='^back$'),
            ],
            ACTIVATION_PROOF: [
                MessageHandler(
                    (filters.VIDEO | filters.PHOTO) & filters.CAPTION,
                    process_activation_proof
                ),
                CallbackQueryHandler(back_to_menu, pattern='^back$'),
            ],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
        per_message=False,
        per_chat=True,
        per_user=True,
    )

    # Add callback handlers for approval/rejection
    application.add_handler(CallbackQueryHandler(admin_approve, pattern='^approve_'))
    application.add_handler(CallbackQueryHandler(admin_reject, pattern='^reject_'))
    application.add_handler(CallbackQueryHandler(process_rejection, pattern='^reason_'))
    
    # Add handlers
    application.add_handler(CommandHandler('help', help_command))
    application.add_handler(CommandHandler('menu', menu_command))
    application.add_handler(admin_conv_handler)
    application.add_handler(conv_handler)
    application.add_error_handler(error)

    # Start the bot
    logger.info("Bot is now running and polling for updates...")
    await application.run_polling(
        drop_pending_updates=True,
        allowed_updates=Update.ALL_TYPES,
        close_loop=True
    )

if __name__ == '__main__':
    asyncio.run(main())