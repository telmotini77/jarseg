package com.jarvis.mobile;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import org.json.JSONObject;

import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.text.DateFormat;
import java.util.Date;
import javax.net.ssl.SSLHandshakeException;

/** Native, credential-protected mobile companion for JARVIS and CyberSeg. */
public final class MainActivity extends Activity {
    private static final String PREFERENCES = "jarvis_mobile_secure";
    private static final String URL_KEY = "secure_server_url";
    private static final String TOKEN_KEY = "mobile_pairing_token";
    private static final String MODE_KEY = "connection_mode";
    private static final String APP_VERSION = "1.1.0";

    private static final int INK = Color.rgb(235, 244, 252);
    private static final int MUTED = Color.rgb(151, 181, 205);
    private static final int NIGHT = Color.rgb(6, 17, 31);
    private static final int PANEL = Color.rgb(16, 36, 55);
    private static final int PANEL_ALT = Color.rgb(20, 48, 70);
    private static final int CYAN = Color.rgb(96, 213, 255);
    private static final int MINT = Color.rgb(65, 222, 171);
    private static final int AMBER = Color.rgb(255, 191, 91);

    private SharedPreferences securePreferences;
    private Snapshot lastSnapshot;
    private String lastError;
    private boolean refreshing;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(NIGHT); getWindow().setNavigationBarColor(NIGHT);
        try {
            MasterKey key = new MasterKey.Builder(this).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build();
            securePreferences = EncryptedSharedPreferences.create(this, PREFERENCES, key,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
        } catch (Exception error) {
            Toast.makeText(this, "No se pudo iniciar el almacén seguro del dispositivo.", Toast.LENGTH_LONG).show(); finish(); return;
        }
        showCurrentOrSetup();
    }

    private void showCurrentOrSetup() {
        String address = securePreferences.getString(URL_KEY, "");
        String token = securePreferences.getString(TOKEN_KEY, "");
        if (address.isEmpty() || token.isEmpty()) showSetup(); else showDashboard();
    }

    private void showSetup() {
        LinearLayout content = screen();
        content.addView(eyebrow("CONFIGURACIÓN PROTEGIDA"), margin(-1, -2, 0, 0, 0, 12));
        content.addView(title("JARVIS Mobile"), margin(-1, -2, 0, 0, 0, 8));
        content.addView(body("Conecta esta app mediante un canal HTTPS autorizado. El token se guarda cifrado en Android y nunca dentro del APK."), margin(-1, -2, 0, 0, 0, 24));

        LinearLayout setupCard = card(PANEL, 28); setupCard.setPadding(28, 26, 28, 26);
        setupCard.addView(section("Conexión"), margin(-1, -2, 0, 0, 0, 5));
        setupCard.addView(caption("Selecciona una URL HTTPS de JARVIS."), margin(-1, -2, 0, 0, 0, 14));
        EditText address = field("https://jarvis.tu-red-privada"); address.setText(securePreferences.getString(URL_KEY, ""));
        EditText token = field("Token de emparejamiento móvil"); token.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD); token.setText(securePreferences.getString(TOKEN_KEY, ""));
        setupCard.addView(address, margin(-1, -2, 0, 0, 0, 12)); setupCard.addView(token, margin(-1, -2, 0, 0, 0, 18));
        Button wifi = action("Conectar por Wi‑Fi local", CYAN, NIGHT); wifi.setOnClickListener(view -> saveConnection(address, token, "Wi‑Fi local"));
        Button privateAccess = secondary("Usar URL privada HTTPS"); privateAccess.setOnClickListener(view -> saveConnection(address, token, "URL privada"));
        setupCard.addView(wifi, margin(-1, -2, 0, 0, 0, 10)); setupCard.addView(privateAccess, margin(-1, -2, 0, 0, 0, 0));
        content.addView(setupCard, margin(-1, -2, 0, 0, 0, 18));

        LinearLayout note = card(Color.rgb(13, 48, 65), 22); note.setPadding(22, 19, 22, 19);
        note.addView(text("⌁  Seguridad de la conexión", 15, CYAN, true));
        note.addView(caption("Wi‑Fi local requiere que el teléfono y JARVIS estén en la misma red. La URL privada requiere una VPN o un acceso HTTPS administrado."), margin(-1, -2, 0, 8, 0, 0));
        content.addView(note, margin(-1, -2, 0, 0, 0, 20)); content.addView(centered("JARVIS Mobile · v" + APP_VERSION), margin(-1, -2, 0, 0, 0, 10));
        setContentView(scroll(content));
    }

    private void saveConnection(EditText address, EditText token, String mode) {
        String endpoint = normalize(address.getText().toString()); String credential = token.getText().toString().trim();
        if (endpoint == null || credential.length() < 24) { Toast.makeText(this, "Usa una URL HTTPS válida y un token móvil de al menos 24 caracteres.", Toast.LENGTH_LONG).show(); return; }
        securePreferences.edit().putString(URL_KEY, endpoint).putString(TOKEN_KEY, credential).putString(MODE_KEY, mode).apply();
        lastSnapshot = null; lastError = null; showDashboard();
    }

    private void showDashboard() { renderDashboard(); fetchStatus(); }

    private void renderDashboard() {
        LinearLayout content = screen(); String mode = securePreferences.getString(MODE_KEY, "URL privada"); boolean online = lastSnapshot != null && lastSnapshot.online;
        content.addView(eyebrow(online ? "CANAL PROTEGIDO · EN LÍNEA" : "CANAL PROTEGIDO · VERIFICANDO"), margin(-1, -2, 0, 0, 0, 10));
        content.addView(title("JARVIS"), margin(-1, -2, 0, 0, 0, 4)); content.addView(body("Centro de control móvil"), margin(-1, -2, 0, 0, 0, 18));

        LinearLayout hero = card(online ? Color.rgb(11, 70, 73) : PANEL, 30); hero.setPadding(28, 25, 28, 25);
        LinearLayout heroTop = new LinearLayout(this); heroTop.setGravity(Gravity.CENTER_VERTICAL); heroTop.setOrientation(LinearLayout.HORIZONTAL);
        heroTop.addView(statusDot(online ? MINT : AMBER), margin(22, 22, 0, 0, 12, 0)); heroTop.addView(text(online ? "JARVIS está operativo" : refreshing ? "Conectando con JARVIS…" : "Estado pendiente", 19, INK, true), weight(0, -2, 1));
        hero.addView(heroTop, margin(-1, -2, 0, 0, 0, 8)); hero.addView(caption(online ? "La conexión autenticada está activa." : (lastError == null ? "Comprobando el canal HTTPS de forma segura." : lastError)));
        content.addView(hero, margin(-1, -2, 0, 0, 0, 18));

        content.addView(section("Vista general"), margin(-1, -2, 0, 0, 0, 10));
        LinearLayout metrics = new LinearLayout(this); metrics.setOrientation(LinearLayout.HORIZONTAL);
        metrics.addView(metric("AGENTES", lastSnapshot == null ? "—" : lastSnapshot.healthy + "/" + lastSnapshot.total, lastSnapshot == null ? "Sin lectura" : "saludables", CYAN), weightedMargin(0, -2, 1, 0, 0, 7, 0));
        metrics.addView(metric("CYBERSEG", lastSnapshot == null ? "—" : (lastSnapshot.cyberAvailable ? "ON" : "OFF"), lastSnapshot == null ? "Sin lectura" : "vigilancia", lastSnapshot != null && lastSnapshot.cyberAvailable ? MINT : AMBER), weightedMargin(0, -2, 1, 7, 0, 0, 0));
        content.addView(metrics, margin(-1, -2, 0, 0, 0, 18));

        LinearLayout security = card(PANEL_ALT, 28); security.setPadding(27, 24, 27, 24); security.addView(text("CyberSeg", 20, INK, true));
        security.addView(chip(lastSnapshot != null && lastSnapshot.cyberAvailable ? "VIGILANCIA ACTIVA" : "ESPERANDO ESTADO", lastSnapshot != null && lastSnapshot.cyberAvailable ? MINT : AMBER), margin(-2, -2, 0, 10, 0, 12));
        security.addView(body(lastSnapshot == null ? "Recuperando información de protección…" : lastSnapshot.cyberStatus), margin(-1, -2, 0, 0, 0, 12));
        View line = new View(this); line.setBackgroundColor(Color.rgb(48, 91, 115)); security.addView(line, margin(-1, 1, 0, 0, 0, 12)); security.addView(caption(lastSnapshot == null ? "Las alertas aparecerán aquí tras la conexión." : lastSnapshot.alerts));
        content.addView(security, margin(-1, -2, 0, 0, 0, 18));

        Button refresh = action(refreshing ? "Actualizando…" : "Actualizar estado", CYAN, NIGHT); refresh.setEnabled(!refreshing); refresh.setOnClickListener(view -> fetchStatus());
        Button diagnostics = secondary("Diagnóstico de conexión"); diagnostics.setOnClickListener(view -> showDiagnostics());
        Button network = tertiary("Cambiar red o credencial"); network.setOnClickListener(view -> showSetup());
        content.addView(refresh, margin(-1, -2, 0, 0, 0, 10)); content.addView(diagnostics, margin(-1, -2, 0, 0, 0, 10)); content.addView(network, margin(-1, -2, 0, 0, 0, 20));
        content.addView(centered(mode + " · Actualizado " + (lastSnapshot == null ? "—" : lastSnapshot.updatedAt) + " · v" + APP_VERSION), margin(-1, -2, 0, 0, 0, 10));
        setContentView(scroll(content));
    }

    private void showDiagnostics() {
        Uri endpoint = Uri.parse(securePreferences.getString(URL_KEY, "")); String state = lastSnapshot != null && lastSnapshot.online ? "Conectado de forma segura" : "Pendiente de conexión";
        String details = "Estado: " + state + "\nModo: " + securePreferences.getString(MODE_KEY, "URL privada") + "\nServidor: " + (endpoint.getHost() == null ? "No configurado" : endpoint.getHost()) + "\nHTTPS: obligatorio\nToken: guardado de forma cifrada y oculto";
        if (lastError != null) details += "\n\nÚltimo resultado: " + lastError;
        new AlertDialog.Builder(this).setTitle("Diagnóstico seguro").setMessage(details).setPositiveButton("Cerrar", null).show();
    }

    private void fetchStatus() {
        if (refreshing) return; refreshing = true; lastError = null; renderDashboard();
        new Thread(() -> {
            try {
                URL url = new URL(securePreferences.getString(URL_KEY, "") + "/api/mobile/status"); HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setConnectTimeout(8_000); connection.setReadTimeout(8_000); connection.setRequestProperty("Accept", "application/json"); connection.setRequestProperty("X-Jarvis-Mobile-Token", securePreferences.getString(TOKEN_KEY, ""));
                int code = connection.getResponseCode(); if (code != 200) throw new IllegalStateException("HTTP " + code);
                JSONObject payload = new JSONObject(new String(connection.getInputStream().readAllBytes())); JSONObject agents = payload.getJSONObject("agents"); JSONObject cyberseg = payload.getJSONObject("cyberseg");
                Snapshot snapshot = new Snapshot(payload.getBoolean("online"), agents.optInt("healthy", 0), agents.optInt("total", 0), cyberseg.optBoolean("available", false), cyberseg.optString("status", "CyberSeg sin estado"), cyberseg.optString("alerts", "Sin alertas de CyberSeg."), DateFormat.getTimeInstance(DateFormat.SHORT).format(new Date()));
                runOnUiThread(() -> { lastSnapshot = snapshot; refreshing = false; renderDashboard(); });
            } catch (Exception error) { String reason = connectionError(error); runOnUiThread(() -> { lastError = reason; refreshing = false; renderDashboard(); }); }
        }).start();
    }

    private static String connectionError(Exception error) {
        if (error instanceof SSLHandshakeException) return "El certificado HTTPS no fue aceptado por el teléfono.";
        if (error instanceof SocketTimeoutException) return "JARVIS no respondió. Comprueba que ambos dispositivos estén en la misma Wi‑Fi.";
        if (error instanceof ConnectException) return "No se pudo alcanzar la PC. Revisa la red local y la URL.";
        if (error instanceof IllegalStateException) return "El servidor rechazó el token de emparejamiento.";
        return "No se pudo completar HTTPS (" + error.getClass().getSimpleName() + ").";
    }

    private LinearLayout screen() { LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(38, 42, 38, 42); root.setBackgroundColor(NIGHT); return root; }
    private ScrollView scroll(LinearLayout content) { ScrollView view = new ScrollView(this); view.setFillViewport(true); view.addView(content); return view; }
    private LinearLayout card(int color, int radius) { LinearLayout item = new LinearLayout(this); item.setOrientation(LinearLayout.VERTICAL); item.setBackground(round(color, radius)); return item; }
    private TextView title(String value) { return text(value, 35, INK, false); }
    private TextView section(String value) { return text(value, 19, INK, true); }
    private TextView body(String value) { return text(value, 16, MUTED, false); }
    private TextView caption(String value) { return text(value, 14, MUTED, false); }
    private TextView centered(String value) { TextView result = caption(value); result.setGravity(Gravity.CENTER); return result; }
    private TextView eyebrow(String value) { TextView result = text(value, 12, CYAN, true); result.setLetterSpacing(.12f); return result; }
    private TextView text(String value, int size, int color, boolean bold) { TextView item = new TextView(this); item.setText(value); item.setTextSize(size); item.setTextColor(color); item.setLineSpacing(4, 1f); if (bold) item.setTypeface(android.graphics.Typeface.DEFAULT_BOLD); return item; }
    private TextView chip(String value, int color) { TextView item = text(value, 11, color, true); item.setLetterSpacing(.09f); item.setPadding(14, 8, 14, 8); item.setBackground(round(withAlpha(color, 35), 99)); return item; }
    private View statusDot(int color) { View item = new View(this); item.setBackground(round(color, 99)); return item; }
    private LinearLayout metric(String label, String value, String hint, int color) { LinearLayout item = card(PANEL, 22); item.setPadding(20, 19, 20, 19); item.addView(text(label, 11, MUTED, true)); item.addView(text(value, 25, color, true), margin(-1, -2, 0, 5, 0, 3)); item.addView(caption(hint)); return item; }
    private EditText field(String hint) { EditText item = new EditText(this); item.setHint(hint); item.setSingleLine(true); item.setPadding(18, 7, 18, 7); item.setTextColor(INK); item.setHintTextColor(MUTED); item.setBackground(round(Color.rgb(8, 25, 40), 16)); return item; }
    private Button action(String value, int color, int textColor) { Button item = button(value); item.setTextColor(textColor); item.setBackground(round(color, 18)); return item; }
    private Button secondary(String value) { Button item = button(value); item.setTextColor(CYAN); item.setBackground(stroke(PANEL, CYAN, 18)); return item; }
    private Button tertiary(String value) { Button item = button(value); item.setTextColor(MUTED); item.setBackground(round(Color.TRANSPARENT, 18)); return item; }
    private Button button(String value) { Button item = new Button(this); item.setText(value); item.setTextSize(15); item.setAllCaps(false); item.setMinHeight(0); item.setPadding(18, 11, 18, 11); return item; }
    private GradientDrawable round(int color, int radius) { GradientDrawable item = new GradientDrawable(); item.setColor(color); item.setCornerRadius(radius); return item; }
    private GradientDrawable stroke(int fill, int line, int radius) { GradientDrawable item = round(fill, radius); item.setStroke(2, line); return item; }
    private int withAlpha(int color, int alpha) { return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color)); }
    private LinearLayout.LayoutParams margin(int width, int height, int left, int top, int right, int bottom) { LinearLayout.LayoutParams item = new LinearLayout.LayoutParams(width, height); item.setMargins(left, top, right, bottom); return item; }
    private LinearLayout.LayoutParams weight(int width, int height, float weight) { return new LinearLayout.LayoutParams(width, height, weight); }
    private LinearLayout.LayoutParams weightedMargin(int width, int height, float weight, int left, int top, int right, int bottom) { LinearLayout.LayoutParams item = weight(width, height, weight); item.setMargins(left, top, right, bottom); return item; }
    private static String normalize(String value) { String trimmed = value == null ? "" : value.trim().replaceAll("/+$", ""); Uri uri = Uri.parse(trimmed); return "https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null ? trimmed : null; }

    private static final class Snapshot {
        final boolean online, cyberAvailable; final int healthy, total; final String cyberStatus, alerts, updatedAt;
        Snapshot(boolean online, int healthy, int total, boolean cyberAvailable, String cyberStatus, String alerts, String updatedAt) { this.online = online; this.healthy = healthy; this.total = total; this.cyberAvailable = cyberAvailable; this.cyberStatus = cyberStatus; this.alerts = alerts; this.updatedAt = updatedAt; }
    }
}
