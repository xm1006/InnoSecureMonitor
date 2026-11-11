package com.example.innotuidmonitor;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam;

public final class TuidMonitor extends XposedModule {
    private static final String TAG = "InnoTuidMonitor";
    private static final String TARGET_PACKAGE = "com.jifen.qukan";

    // Candidate classes confirmed in the supplied qtt.jar DEX string table.
    private static final String[] TARGET_CLASSES = {
        "com.inno.innosdk.pb.InnoMain",
        "com.inno.innosdk.pb.InnoValue",
        "com.inno.innosecure.InnoSecureUtils"
    };

    private static final Set<String> TARGET_METHODS = new HashSet<>(Arrays.asList(
        "getTuid", "getTk", "loadTuid", "getInnoValue", "secureSo"
    ));

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!TARGET_PACKAGE.equals(param.getPackageName())) return;

        ClassLoader loader = param.getClassLoader();
        log(android.util.Log.INFO, TAG,
            "API=" + getApiVersion() + " package=" + param.getPackageName());

        for (String className : TARGET_CLASSES) {
            hookCandidateClass(loader, className);
        }
    }

    private void hookCandidateClass(ClassLoader loader, String className) {
        try {
            Class<?> clazz = Class.forName(className, false, loader);
            int count = 0;

            for (Method method : clazz.getDeclaredMethods()) {
                if (!TARGET_METHODS.contains(method.getName())) continue;
                method.setAccessible(true);
                final Method hooked = method;
                final String signature = method.toGenericString();

                hook(method).setId("diag:" + className + ":" + method.getName()
                        + ":" + Arrays.toString(method.getParameterTypes()))
                    .intercept(chain -> {
                        Object[] args = chain.getArgs().toArray();
                        log(android.util.Log.INFO, TAG, "ENTER " + signature
                                + " static=" + Modifier.isStatic(hooked.getModifiers())
                                + " args=" + describeArgs(args));
                        long started = System.nanoTime();
                        try {
                            Object result = chain.proceed();
                            log(android.util.Log.INFO, TAG, "EXIT " + signature
                                    + " result=" + describeResult(result)
                                    + " elapsedMs=" + ((System.nanoTime() - started) / 1_000_000L));
                            return result;
                        } catch (Throwable t) {
                            log(android.util.Log.ERROR, TAG,
                                    "THROW " + signature + " " + t.getClass().getName()
                                    + ": " + String.valueOf(t.getMessage()));
                            throw t;
                        }
                    });
                count++;
                log(android.util.Log.INFO, TAG, "HOOKED " + signature);
            }

            if (count == 0) {
                log(android.util.Log.WARN, TAG,
                        "No candidate methods found in " + className);
            }
        } catch (ClassNotFoundException e) {
            log(android.util.Log.WARN, TAG, "Class not found: " + className);
        } catch (Throwable t) {
            log(android.util.Log.ERROR, TAG, "Hook setup failed: " + className, t);
        }
    }

    // Avoid writing TK/TUID/device/account identifiers to logcat.
    // Primitive test values and argument types remain visible for call-flow diagnosis.
    private static String describeArgs(Object[] args) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < args.length; i++) {
            if (i > 0) out.append(", ");
            Object value = args[i];
            if (value == null) {
                out.append(i).append(":null");
            } else if (value instanceof Number || value instanceof Boolean
                    || value instanceof Character) {
                out.append(i).append(":").append(value.getClass().getSimpleName())
                    .append("=").append(value);
            } else if (value instanceof String) {
                String s = (String) value;
                out.append(i).append(":String(len=").append(s.length()).append(")");
            } else if (value instanceof byte[]) {
                out.append(i).append(":byte[](len=").append(((byte[]) value).length).append(")");
            } else {
                out.append(i).append(":").append(value.getClass().getName());
            }
        }
        return out.append("]").toString();
    }

    private static String describeResult(Object result) {
        if (result == null) return "null";
        if (result instanceof String) {
            return "String(len=" + ((String) result).length() + ")";
        }
        if (result instanceof byte[]) {
            return "byte[](len=" + ((byte[]) result).length + ")";
        }
        if (result instanceof Number || result instanceof Boolean) {
            return result.getClass().getSimpleName() + "(" + result + ")";
        }
        return result.getClass().getName();
    }
}
