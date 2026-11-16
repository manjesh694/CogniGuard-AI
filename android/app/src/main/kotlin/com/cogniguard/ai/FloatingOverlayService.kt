package com.cogniguard.ai

import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.IBinder
import android.view.Gravity
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView

/**
 * CogniGuard AI: Truecaller-Style Floating Overlay Service
 * Draws a floating heads-up message box directly over Google Messages, WhatsApp, or the home screen.
 * Displays:
 *  - 🔴 RED corner mark on Scams & Predatory Loans (with link neutralization)
 *  - 🟢 GREEN corner mark on Authentic Bank SMS & 2FA OTP codes
 */
class FloatingOverlayService : Service() {

    private var windowManager: WindowManager? = null
    private var overlayView: View? = null

    companion object {
        const val EXTRA_SENDER = "extra_sender"
        const val EXTRA_BODY = "extra_body"
        const val EXTRA_IS_SCAM = "extra_is_scam"
        const val EXTRA_THREAT_REASON = "extra_threat_reason"

        fun showOverlay(context: Context, sender: String, body: String, isScam: Boolean, threatReason: String) {
            val intent = Intent(context, FloatingOverlayService::class.java).apply {
                putExtra(EXTRA_SENDER, sender)
                putExtra(EXTRA_BODY, body)
                putExtra(EXTRA_IS_SCAM, isScam)
                putExtra(EXTRA_THREAT_REASON, threatReason)
            }
            context.startService(intent)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val sender = intent?.getStringExtra(EXTRA_SENDER) ?: "Unknown"
        val body = intent?.getStringExtra(EXTRA_BODY) ?: ""
        val isScam = intent?.getBooleanExtra(EXTRA_IS_SCAM, false) ?: false
        val reason = intent?.getStringExtra(EXTRA_THREAT_REASON) ?: ""

        displayFloatingMessageBox(sender, body, isScam, reason)
        return START_NOT_STICKY
    }

    private fun displayFloatingMessageBox(sender: String, body: String, isScam: Boolean, reason: String) {
        removeCurrentOverlay()

        windowManager = getSystemService(Context.WINDOW_SERVICE) as WindowManager

        val layoutFlag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            layoutFlag,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = 120 // Position below status bar like Truecaller
        }

        // Programmatic creation of Truecaller-style floating card
        val card = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(36, 32, 36, 32)
            
            val backgroundDrawable = GradientDrawable().apply {
                cornerRadius = 32f
                if (isScam) {
                    setColor(Color.parseColor("#1f070b"))
                    setStroke(4, Color.parseColor("#ef4444")) // RED BORDER
                } else {
                    setColor(Color.parseColor("#051c14"))
                    setStroke(4, Color.parseColor("#10b981")) // GREEN BORDER
                }
            }
            background = backgroundDrawable
        }

        // Top Row: Corner Badge & App Branding
        val headerRow = android.widget.RelativeLayout(this).apply {
            layoutParams = android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

        val titleView = TextView(this).apply {
            text = "🛡️ CogniGuard AI Airlock"
            setTextColor(Color.parseColor("#38bdf8"))
            textSize = 12f
        }
        headerRow.addView(titleView)

        // Corner Badge (RED for scam, GREEN for original)
        val cornerBadge = TextView(this).apply {
            text = if (isScam) "🔴 🚨 FAKE / SCAM" else "🟢 ✅ VERIFIED BANK"
            setTextColor(if (isScam) Color.parseColor("#fca5a5") else Color.parseColor("#6ee7b7"))
            textSize = 10f
            setPadding(16, 6, 16, 6)
            background = GradientDrawable().apply {
                cornerRadius = 14f
                setColor(if (isScam) Color.parseColor("#3f1218") else Color.parseColor("#0a3828"))
                setStroke(2, if (isScam) Color.parseColor("#ef4444") else Color.parseColor("#10b981"))
            }
            val lp = android.widget.RelativeLayout.LayoutParams(
                android.widget.RelativeLayout.LayoutParams.WRAP_CONTENT,
                android.widget.RelativeLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                addRule(android.widget.RelativeLayout.ALIGN_PARENT_END)
            }
            layoutParams = lp
        }
        headerRow.addView(cornerBadge)
        card.addView(headerRow)

        // Sender Name
        val senderView = TextView(this).apply {
            text = sender
            textSize = 17f
            setTextColor(Color.WHITE)
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setPadding(0, 16, 0, 8)
        }
        card.addView(senderView)

        // Message Snippet
        val snippetView = TextView(this).apply {
            text = body
            textSize = 13f
            setTextColor(Color.parseColor("#cbd5e1"))
            setPadding(0, 0, 0, 16)
        }
        card.addView(snippetView)

        // Reason Banner
        val reasonView = TextView(this).apply {
            text = if (isScam) "⚠️ $reason" else "🛡️ $reason"
            textSize = 11f
            setTextColor(if (isScam) Color.parseColor("#f87171") else Color.parseColor("#34d399"))
            setPadding(0, 0, 0, 20)
        }
        card.addView(reasonView)

        // Action Buttons Row
        val btnRow = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.HORIZONTAL
            weightSum = 2f
        }

        val primaryBtn = Button(this).apply {
            text = if (isScam) "🚨 Block Sender" else "✅ Acknowledge"
            setBackgroundColor(if (isScam) Color.parseColor("#ef4444") else Color.parseColor("#10b981"))
            setTextColor(Color.WHITE)
            layoutParams = android.widget.LinearLayout.LayoutParams(0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                removeCurrentOverlay()
                stopSelf()
            }
        }
        btnRow.addView(primaryBtn)

        val dismissBtn = Button(this).apply {
            text = "✕ Dismiss"
            setBackgroundColor(Color.parseColor("#1e293b"))
            setTextColor(Color.parseColor("#94a3b8"))
            layoutParams = android.widget.LinearLayout.LayoutParams(0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginStart = 16
            }
            setOnClickListener {
                removeCurrentOverlay()
                stopSelf()
            }
        }
        btnRow.addView(dismissBtn)
        card.addView(btnRow)

        overlayView = card
        windowManager?.addView(overlayView, params)
    }

    private fun removeCurrentOverlay() {
        overlayView?.let {
            windowManager?.removeView(it)
            overlayView = null
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        removeCurrentOverlay()
    }
}
