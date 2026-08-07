package dev.mikko.log4jcheck;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 归档遍历。{@link Scanner}(找构件版本)和 {@link ConfigScan}(找 log4j2 配置)
 * 都要穿透 fat jar / WAR,所以这段只写一份。
 *
 * <p>能穿透:普通 jar、Spring Boot fat jar({@code BOOT-INF/lib/}、{@code BOOT-INF/classes/})、
 * 传统 WAR({@code WEB-INF/lib/}、{@code WEB-INF/classes/}),以及被 shade 进同一个归档的情形。
 */
public final class Archives {

    /** 递归展开深度上限。fat jar 内的 jar 一般不再套 jar,留 2 层足够且防病态归档。 */
    public static final int DEFAULT_DEPTH = 2;

    /** 单个条目解压后的大小上限,防 zip bomb 把内存吃光。 */
    private static final long MAX_ENTRY_BYTES = 64L * 1024 * 1024;

    /** 每读到一个条目就回调一次。{@code path} 用 {@code !/} 表示「在这个归档里面」。 */
    public interface EntryVisitor {
        void visit(String path, byte[] data);
    }

    /**
     * 遍历一个归档里的全部文件条目(含嵌套归档内的)。
     *
     * @param path     归档路径,用于拼出可读的证据路径
     * @param bytes    归档内容
     * @param maxDepth 还能再往里展开几层
     * @param visitor  每个文件条目的回调
     * @param warn     告警回调 —— 🔴 解析失败必须报出来,因为「没扫到」和「你很安全」长得一样
     */
    public static int walk(String path, byte[] bytes, int maxDepth,
                           EntryVisitor visitor, Consumer<String> warn) {
        List<String> innerPaths = new ArrayList<>();
        List<byte[]> innerBytes = new ArrayList<>();
        int entries = 0;

        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                entries++;
                if (e.isDirectory()) {
                    continue;
                }
                // 🔴 ZIP 规范要求用 '/',但现实里存在写成 '\' 的归档
                // (PowerShell 的 Compress-Archive 就是一例)。只认 '/' 的话这类归档一条都扫不出来,
                // 而「没扫到」看起来和「你很安全」一模一样(第 6 注踩过)。
                String name = e.getName().replace('\\', '/');
                byte[] data = readLimited(zis, warn, path + "!/" + name);
                if (data == null) {
                    continue;
                }
                String full = path + "!/" + name;
                visitor.visit(full, data);
                if (name.toLowerCase().endsWith(".jar") && maxDepth > 0) {
                    innerPaths.add(full);
                    innerBytes.add(data);
                }
            }
        } catch (IOException | IllegalArgumentException ex) {
            warn.accept("归档解析失败 " + path + ":" + ex.getMessage()
                    + "(🔴 这不等于「里面什么都没有」,请手工确认)");
            return -1;
        }
        for (int i = 0; i < innerPaths.size(); i++) {
            walk(innerPaths.get(i), innerBytes.get(i), maxDepth - 1, visitor, warn);
        }
        return entries;
    }

    /**
     * 一个**看起来是归档**的文件必须至少解出一个条目,否则告警。
     *
     * <p>🔴 <b>由来:建造时实测出来的静默故障。</b>把一个不是 zip 的文件
     * (截断的 jar、下载到一半的 jar、其实是 HTML 错误页的 jar)喂给 {@link ZipInputStream},
     * 它 <b>返回 0 个条目并且不抛任何异常</b> —— 于是扫描结果是「什么都没扫到」,
     * 而那和「你很安全」长得一模一样。第 6 注和第 4 注各踩过一次同型的洞
     * (`10-教训.md`「静默故障最贵」),所以这里把它变成一句响的告警。
     *
     * @param entries {@link #walk} 的返回值;-1 表示已经报过解析失败了
     */
    public static void warnIfEmpty(String path, int entries, Consumer<String> warn) {
        if (entries == 0) {
            warn.accept("这个文件看起来是归档,但一个条目都解不出来:" + path
                    + "(🔴 很可能不是有效的 zip/jar —— 截断、下载不全,或其实是个 HTML 错误页。"
                    + "**这不等于「里面没有 log4j」**)");
        }
    }

    private static byte[] readLimited(ZipInputStream zis, Consumer<String> warn, String what) {
        try {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            long total = 0;
            int n;
            while ((n = zis.read(buf)) > 0) {
                total += n;
                if (total > MAX_ENTRY_BYTES) {
                    warn.accept("归档条目过大已跳过:" + what
                            + "(🔴 这不等于「它里面没有东西」)");
                    return null;
                }
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        } catch (IOException e) {
            warn.accept("读取归档条目失败 " + what + ":" + e.getMessage());
            return null;
        }
    }

    private Archives() {
    }
}
