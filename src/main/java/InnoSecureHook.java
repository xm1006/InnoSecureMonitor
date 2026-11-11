import android.content.Context;
import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.util.Log;

import java.net.URI;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class InnoSecureHook implements IXposedHookLoadPackage {
    private static final String TAG = "InnoSecureMonitor";
    private static final String TARGET = "com.jifen.qukan";
    private static final String CLASS_NAME = "com.inno.innosecure.InnoSecureUtils";

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) {
        if (!TARGET.equals(lpparam.packageName)) return;

        hookSecureSo(lpparam);
        hookWebViewDiagnostics();
    }

    private void hookSecureSo(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> target = XposedHelpers.findClass(CLASS_NAME, lpparam.classLoader);
            int declared = 0;
            for (java.lang.reflect.Method method : target.getDeclaredMethods()) {
                if ("secureSo".equals(method.getName())) {
                    declared++;
                    log("secureSo discovered: " + method.toGenericString());
                }
            }
            if (declared == 0) {
                log("secureSo NOT FOUND in " + CLASS_NAME
                        + "; loader=" + String.valueOf(lpparam.classLoader));
                return;
            }

            java.util.Set<XC_MethodHook.Unhook> installed =
                    XposedBridge.hookAllMethods(target, "secureSo", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    StringBuilder out = new StringBuilder("secureSo ENTER method=")
                            .append(param.method.toString())
                            .append(" thread=").append(Thread.currentThread().getName())
                            .append(" args=[");
                    if (param.args != null) {
                        for (int i = 0; i < param.args.length; i++) {
                            if (i > 0) out.append(", ");
                            out.append(i).append("=").append(describeValue(param.args[i]));
                        }
                    }
                    out.append("]");
                    log(out.toString());
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (param.hasThrowable()) {
                        Throwable error = param.getThrowable();
                        log("secureSo THROW method=" + param.method
                                + " exception=" + Log.getStackTraceString(error));
                    } else {
                        log("secureSo RETURN method=" + param.method
                                + " result=" + describeValue(param.getResult()));
                    }
                }
            });
            log("secureSo hook installed: overloads=" + installed.size()
                    + " declared=" + declared);
        } catch (Throwable t) {
            log("secureSo hook install failed: " + Log.getStackTraceString(t));
            XposedBridge.log(t);
        }
    }

    // Print readable text while masking fields commonly used for credentials or device identity.
    private static String describeValue(Object value) {
        if (value == null) return "null";
        if (value instanceof Context) {
            return "Context(package=" + ((Context) value).getPackageName() + ")";
        }
        if (value instanceof String) {
            String s = (String) value;
            return "String(length=" + s.length() + ", text=" + quoteForLog(redactSensitive(s)) + ")";
        }
        if (value instanceof byte[]) {
            byte[] bytes = (byte[]) value;
            String decoded = new String(bytes, StandardCharsets.UTF_8);
            if (isReadableText(decoded)) {
                return "byte[](length=" + bytes.length + ", utf8="
                        + quoteForLog(redactSensitive(decoded)) + ")";
            }
            return "byte[](length=" + bytes.length + ", sha256="
                    + sha256Bytes(bytes) + ", non-text)";
        }
        if (value instanceof Number || value instanceof Boolean || value instanceof Character
                || value instanceof Enum<?>) {
            return value.getClass().getSimpleName() + "(" + String.valueOf(value) + ")";
        }
        Class<?> type = value.getClass();
        if (type.isArray()) {
            return type.getComponentType().getTypeName() + "[]"
                    + "(length=" + java.lang.reflect.Array.getLength(value) + ")";
        }
        return type.getName();
    }

    private static String redactSensitive(String input) {
        String s = input;
        // Mask values attached to common secret/identity field names.
        s = s.replaceAll("(?i)((?:authorization|access_token|refresh_token|token|cookie|"
                + "password|passwd|secret|api[_-]?key|session[_-]?id|device[_-]?id|android[_-]?id)"
                + "[\\\"']?\\s*[:=]\\s*[\\\"']?)[^\\\"'&,}\\s]+", "$1<redacted>");
        s = s.replaceAll("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}",
                "<jwt-redacted>");
        return s;
    }

    private static boolean isReadableText(String s) {
        if (s == null || s.length() == 0 || s.indexOf('\uFFFD') >= 0) return false;
        int checked = Math.min(s.length(), 4096);
        for (int i = 0; i < checked; i++) {
            char ch = s.charAt(i);
            if (Character.isISOControl(ch) && ch != '\n' && ch != '\r' && ch != '\t') {
                return false;
            }
        }
        return true;
    }

    private static String quoteForLog(String s) {
        if (s == null) return "null";
        String value = s.replace("\\", "\\\\")
                .replace("\r", "\\r").replace("\n", "\\n")
                .replace("\t", "\\t");
        if (value.length() > 4096) value = value.substring(0, 4096) + "...<truncated>";
        return "\"" + value + "\"";
    }

    private static String sha256Bytes(byte[] bytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder out = new StringBuilder(digest.length * 2);
            for (byte b : digest) out.append(String.format(Locale.US, "%02x", b & 0xff));
            return out.toString();
        } catch (Exception e) {
            return "unavailable";
        }
    }

    private void hookWebViewDiagnostics() {
        try {
            XposedBridge.hookAllMethods(WebView.class, "loadUrl", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        log("WebView.loadUrl url=" + safeUrl((String) param.args[0]));
                    }
                }
            });
            XposedBridge.hookAllMethods(WebView.class, "postUrl", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        log("WebView.postUrl url=" + safeUrl((String) param.args[0]));
                    }
                }
            });
            XposedBridge.hookAllMethods(WebView.class, "setWebViewClient", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    Object client = param.args != null && param.args.length > 0 ? param.args[0] : null;
                    log("WebView.setWebViewClient client="
                            + (client == null ? "null" : client.getClass().getName()));
                }
            });

            hookWebViewClientCallback("onReceivedError",
                    WebView.class, WebResourceRequest.class, WebResourceError.class);
            hookWebViewClientCallback("onReceivedHttpError",
                    WebView.class, WebResourceRequest.class, WebResourceResponse.class);
            hookWebViewClientCallback("onReceivedSslError",
                    WebView.class, SslErrorHandler.class, SslError.class);
            hookWebViewClientCallback("onPageStarted",
                    WebView.class, String.class, android.graphics.Bitmap.class);
            hookWebViewClientCallback("onPageFinished",
                    WebView.class, String.class);

            log("WebView diagnostics installed (observe-only; SSL errors are not bypassed)");
        } catch (Throwable t) {
            log("WebView diagnostic hook setup issue: " + t.getClass().getName()
                    + " " + safeMessage(t));
            XposedBridge.log(t);
        }
    }

    private void hookWebViewClientCallback(String method, Object... parameterTypes) {
        try {
            Class<?>[] types = new Class<?>[parameterTypes.length];
            for (int i = 0; i < parameterTypes.length; i++) types[i] = (Class<?>) parameterTypes[i];
            XposedBridge.hookAllMethods(WebViewClient.class, method, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    StringBuilder b = new StringBuilder("WebViewClient.")
                            .append(method).append(" ");
                    for (Object arg : param.args) {
                        if (arg instanceof WebResourceRequest) {
                            b.append("url=").append(safeUrl(((WebResourceRequest) arg).getUrl().toString())).append(" ");
                        } else if (arg instanceof WebResourceError) {
                            WebResourceError e = (WebResourceError) arg;
                            b.append("errorCode=").append(e.getErrorCode())
                             .append(" description=").append(e.getDescription()).append(" ");
                        } else if (arg instanceof WebResourceResponse) {
                            WebResourceResponse r = (WebResourceResponse) arg;
                            b.append("httpStatus=").append(r.getStatusCode())
                             .append(" reason=").append(r.getReasonPhrase()).append(" ");
                        } else if (arg instanceof SslError) {
                            SslError e = (SslError) arg;
                            b.append("sslPrimaryError=").append(e.getPrimaryError())
                             .append(" url=").append(safeUrl(e.getUrl())).append(" ");
                        } else if (arg instanceof String) {
                            b.append("url=").append(safeUrl((String) arg)).append(" ");
                        }
                    }
                    log(b.toString());
                }
            });
        } catch (Throwable t) {
            log("Callback hook unavailable: " + method + " " + safeMessage(t));
        }
    }

    private static String safeUrl(String value) {
        if (value == null) return "null";
        try {
            URI u = URI.create(value);
            String host = u.getHost() == null ? "" : u.getHost();
            String path = u.getPath() == null ? "" : u.getPath();
            return u.getScheme() + "://" + host + path + (u.getQuery() == null ? "" : "?<query-redacted>");
        } catch (Throwable ignored) {
            return value.length() > 180 ? value.substring(0, 180) : value;
        }
    }

    private static String fingerprint(Object value) {
        if (value == null) return "null";
        if (!(value instanceof String)) return "type=" + value.getClass().getName();
        String s = (String) value;
        return "type=String,len=" + s.length() + ",sha256=" + sha256(s);
    }

    private static String sha256(String s) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder(digest.length * 2);
            for (byte b : digest) out.append(String.format(Locale.US, "%02x", b & 0xff));
            return out.toString();
        } catch (Exception e) {
            return "unavailable";
        }
    }

    private static String safeMessage(Throwable t) {
        String m = t.getMessage();
        if (m == null) return "";
        return m.length() > 180 ? m.substring(0, 180) : m;
    }

    private static void log(String message) {
        Log.i(TAG, message);
        XposedBridge.log(TAG + ": " + message);
    }
}
