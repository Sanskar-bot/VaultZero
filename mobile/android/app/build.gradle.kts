// VaultZero Android — App-level build.gradle.kts (placeholder)
// Implementation: Day 10-11
//
// This will configure:
// - Kotlin + Jetpack Compose
// - Android Keystore crypto APIs
// - BiometricPrompt dependency
// - libsodium-jni for Argon2id
// - Retrofit for backend API calls
// - Room for local encrypted storage

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.vaultzero"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.vaultzero"
        minSdk = 26  // Android 8.0 — required for AutofillService
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

// TODO: Day 10-11 — add full dependency list
