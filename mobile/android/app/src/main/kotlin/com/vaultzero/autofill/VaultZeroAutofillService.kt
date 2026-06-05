/**
 * VaultZero — AutofillService (placeholder)
 *
 * Implements Android's AutofillService API (Android 8.0+):
 * - onFillRequest: parse AssistStructure for username/password fields
 * - Match app packageName or webDomain to vault entries
 * - Return FillResponse with Dataset objects (native autofill dropdown)
 * - Require BiometricPrompt before filling credentials
 *
 * SECURITY:
 * - Vault key stored in Android Keystore (hardware-backed TEE)
 * - Never stores keys in SharedPreferences
 * - Clears sensitive data from memory after use
 *
 * Implementation: Day 10-11
 */

package com.vaultzero.autofill

// TODO: Day 10-11 — implement VaultZeroAutofillService
