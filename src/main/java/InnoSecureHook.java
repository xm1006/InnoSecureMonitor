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
            XposedHelpers.findAndHookMethod(target, "secureSo",
                    Context.class, String.class, String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Object c = param.args[0];
                    String pkg = c instanceof Context ? ((Context) c).getPackageName() : "not-context";
                    // Do not log raw security inputs. Log type, length and stable fingerprint.
                    log("secureSo ENTER contextPackage=" + pkg
                            + " arg1=" + fingerprint(param.args[1])
                            + " arg2=" + fingerprint(param.args[2]));
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (param.hasThrowable()) {
                        Throwable t = param.getThrowable();
                        log("secureSo THROW type=" + t.getClass().getName()
                                + " message=" + safeMessage(t));
                    } else {
                        log("secureSo RETURN " + fingerprint(param.getResult()));
                    }
                }
            });
            log("Hook installed: " + CLASS_NAME + ".secureSo(Context,String,String)");
        } catch (Throwable t) {
            log("secureSo hook install failed: " + t.getClass().getName()
                    + " " + safeMessage(t));
            XposedBridge.log(t);
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
