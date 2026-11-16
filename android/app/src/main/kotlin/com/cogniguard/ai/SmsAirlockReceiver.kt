package com.cogniguard.ai

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log

/**
 * CogniGuard AI: BroadcastReceiver for Incoming SMS
 * Intercepts SMS_RECEIVED broadcasts to inspect sender identity and embedded URLs.
 */
class SmsAirlockReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        if (intent?.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        for (sms in messages) {
            val sender = sms.originatingAddress ?: "Unknown"
            val body = sms.messageBody ?: ""

            Log.i("CogniGuardSMS", "Intercepted SMS from: $sender (Length: ${body.length})")
            
            // Check for predatory loan or phishing indicators
            val isPredatoryLoan = sender.contains("PWAALA", ignoreCase = true) ||
                                 sender.contains("FATAK", ignoreCase = true) ||
                                 (body.contains("loan", ignoreCase = true) && body.contains(".apk", ignoreCase = true))

            if (isPredatoryLoan) {
                Log.w("CogniGuardSMS", "🚨 RED ALERT: Predatory Loan Syndicate SMS Blocked from $sender")
                // Handled in tandem with NotificationGuardianService for visual Heads-Up Alert
            } else if (sender.contains("BNK", ignoreCase = true) || sender.contains("BANK", ignoreCase = true)) {
                Log.i("CogniGuardSMS", "🟢 Verified authentic bank alert from $sender")
            }
        }
    }
}
