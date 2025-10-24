// hma_ko.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/limits.h>

#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1)

static const char *deny_list[] = {
    "com.silverlab.app.deviceidchanger.free",
    "me.bingyue.IceCore",
    "com.modify.installer",
    "o.dyoo",
    "com.zhufucdev.motion_emulator",
    "me.simpleHook",
    "com.vipkill",
    "io.github.a13e300.ksuwebui",
    "com.demo.serendipity",
    "me.iacn.biliroaming",
    "me.teble.xposed.autodaily",
    "com.example.ourom",
    "dialog.box",
    "top.hookvip.pro",
    "tornaco.apps.shortx",
    "moe.fuqiuluo.portal",
    "com.github.tianma8023.xposed.smscode",
    "moe.shizuku.privileged.api",
    "lin.xposed",
    "com.lerist.fakelocation",
    "com.yxer.packageinstalles",
    "xzr.hkf",
    "web1n.stopapp",
    "Hook.JiuWu.Xp",
    "io.github.qauxv",
    "com.houvven.guise",
    "xzr.konabess",
    "com.xayah.databackup.foss",
    "com.sevtinge.hyperceiler",
    "github.tornaco.android.thanos",
    "nep.timeline.freezer",
    "cn.geektang.privacyspace",
    "org.lsposed.lspatch",
    "zako.zako.zako",
    "com.topmiaohan.hidebllist",
    "com.tsng.hidemyapplist",
    "com.tsng.pzyhrx.hma",
    "com.rifsxd.ksunext",
    "com.byyoung.setting",
    "com.omarea.vtools",
    "cn.myflv.noactive",
    "io.github.vvb2060.magisk",
    "com.bug.hookvip",
    "com.junge.algorithmAidePro",
    "bin.mt.termex",
    "tmgp.atlas.toolbox",
    "com.wn.app.np",
    "com.sukisu.ultra",
    "ru.maximoff.apktool",
    "top.bienvenido.saas.i18n",
    "com.syyf.quickpay",
    "tornaco.apps.shortx.ext",
    "com.mio.kitchen",
    "eu.faircode.xlua",
    "com.dna.tools",
    "cn.myflv.monitor.noactive",
    "com.yuanwofei.cardemulator.pro",
    "com.termux",
    "com.suqi8.oshin",
    "me.hd.wauxv",
    "have.fun",
    "miko.client",
    "com.kooritea.fcmfix",
    "com.twifucker.hachidori",
    "com.luckyzyx.luckytool",
    "com.padi.hook.hookqq",
    "cn.lyric.getter",
    "com.parallelc.micts",
    "me.plusne",
    "com.hchen.appretention",
    "com.hchen.switchfreeform",
    "name.monwf.customiuizer",
    "com.houvven.impad",
    "cn.aodlyric.xiaowine",
    "top.sacz.timtool",
    "nep.timeline.re_telegram",
    "com.fuck.android.rimet",
    "cn.kwaiching.hook",
    "cn.android.x",
    "cc.aoeiuv020.iamnotdisabled.hook",
    "vn.kwaiching.tao",
    "com.nnnen.plusne",
    "com.fkzhang.wechatxposed",
    "one.yufz.hmspush",
    "cn.fuckhome.xiaowine",
    "com.fankes.tsbattery",
    "com.rifsxd.ksunext",
    "com.rkg.IAMRKG",
    "me.gm.cleaner",
    "moe.shizuku.redirectstorage",
    "com.ddm.qute",
    "io.github.vvb2060.magisk",
    "kk.dk.anqu",
    "com.qq.qcxm",
    "com.wei.vip",
    "dknb.con",
    "dknb.coo8",
    "com.tencent.jingshi",
    "com.tencent.JYNB",
    "com.apocalua.run",
    "com.coderstory.toolkit",
    "com.didjdk.adbhelper",
    "org.lsposed.manager",
    "io.github.Retmon403.oppotheme",
    "com.fankes.enforcehighrefreshrate",
    "es.chiteroman.bootloaderspoofer",
    "com.hchai.rescueplan",
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

static int is_in_deny_list(const char *path)
{
    const char *p = path;
    size_t prefix_len = strlen(TARGET_PATH);
    if (strncmp(p, TARGET_PATH, prefix_len) != 0)
        return 0;
    const char *pkg = p + prefix_len;
    char pkgname[128];
    size_t i = 0;
    while (*pkg && *pkg != '/' && *pkg != '\\' && i < sizeof(pkgname) - 1)
        pkgname[i++] = *pkg++;
    pkgname[i] = '\0';
    {
        size_t j;
        for (j = 0; j < DENY_LIST_SIZE; ++j)
            if (strcmp(pkgname, deny_list[j]) == 0)
                return 1;
    }
    return 0;
}

static int copy_path_from_user_safe(const char __user *u, char *kbuf, size_t kbuflen)
{
    long ret;
    if (!u)
        return -EINVAL;
    ret = strncpy_from_user(kbuf, u, kbuflen);
    if (ret <= 0 || ret >= kbuflen)
        return -EFAULT;
    kbuf[ret] = '\0';
    return 0;
}

#ifdef CONFIG_ARM64
static inline const char __user *get_arg_ptr(struct pt_regs *regs, int n)
{
    return (const char __user *)regs->regs[n];
}
#else
static inline const char __user *get_arg_ptr(struct pt_regs *regs, int n)
{
#if defined(CONFIG_X86)
    if (n == 0) return (const char __user *)regs->di;
    if (n == 1) return (const char __user *)regs->si;
    if (n == 2) return (const char __user *)regs->dx;
    if (n == 3) return (const char __user *)regs->r10;
    if (n == 4) return (const char __user *)regs->r8;
    if (n == 5) return (const char __user *)regs->r9;
#endif
    return NULL;
}
#endif

static int pre_mkdirat_handler(struct kprobe *kp, struct pt_regs *regs)
{
    char path[PATH_MAX];
    const char __user *user_path;
#ifdef CONFIG_ARM64
    user_path = get_arg_ptr(regs, 1);
#else
    user_path = get_arg_ptr(regs, 1);
#endif
    if (!user_path)
        return 0;
    if (copy_path_from_user_safe(user_path, path, sizeof(path)) != 0)
        return 0;
    if (strncmp(path, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_in_deny_list(path)) {
            pr_warn("[HMAKO]mkdirat: Denied by deny_list to create %s\n", path);
#ifdef CONFIG_ARM64
            regs->regs[0] = -EACCES;
            regs->pc += 4;
#endif
        }
    }
    return 0;
}

static int pre_chdir_handler(struct kprobe *kp, struct pt_regs *regs)
{
    char path[PATH_MAX];
    const char __user *user_path;
#ifdef CONFIG_ARM64
    user_path = get_arg_ptr(regs, 0);
#else
    user_path = get_arg_ptr(regs, 0);
#endif
    if (!user_path)
        return 0;
    if (copy_path_from_user_safe(user_path, path, sizeof(path)) != 0)
        return 0;
    if (strncmp(path, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_in_deny_list(path)) {
#ifdef CONFIG_ARM64
            pr_warn("[HMAKO]chdir: Denied by deny_list to %s\n", path);
            regs->regs[0] = -ENOENT;
            regs->pc += 4;
#endif
        }
    }
    return 0;
}

static int pre_unlinkat_handler(struct kprobe *kp, struct pt_regs *regs)
{
    char path[PATH_MAX];
    const char __user *user_path;
    unsigned long flags_val;
#ifdef CONFIG_ARM64
    user_path = get_arg_ptr(regs, 1);
    flags_val = regs->regs[2];
#else
    user_path = get_arg_ptr(regs, 1);
    flags_val = 0;
#endif
    if (!user_path)
        return 0;
    if (copy_path_from_user_safe(user_path, path, sizeof(path)) != 0)
        return 0;
    if ((flags_val & 0x200) && strncmp(path, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_in_deny_list(path)) {
#ifdef CONFIG_ARM64
            pr_warn("[HMAKO]rmdir/unlinkat: Denied by deny_list to %s\n", path);
            regs->regs[0] = -ENOENT;
            regs->pc += 4;
#endif
        }
    }
    return 0;
}

static int pre_fstatat_handler(struct kprobe *kp, struct pt_regs *regs)
{
    char path[PATH_MAX];
    const char __user *user_path;
#ifdef CONFIG_ARM64
    user_path = get_arg_ptr(regs, 1);
#else
    user_path = get_arg_ptr(regs, 1);
#endif
    if (!user_path)
        return 0;
    if (copy_path_from_user_safe(user_path, path, sizeof(path)) != 0)
        return 0;
    if (strncmp(path, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_in_deny_list(path)) {
#ifdef CONFIG_ARM64
            pr_warn("[HMAKO]fstatat/stat: Denied by deny_list to %s\n", path);
            regs->regs[0] = -ENOENT;
            regs->pc += 4;
#endif
        }
    }
    return 0;
}

static struct kprobe kp_mkdirat = {
    .symbol_name = "__arm64_sys_mkdirat",
    .pre_handler = pre_mkdirat_handler,
};
static struct kprobe kp_chdir = {
    .symbol_name = "__arm64_sys_chdir",
    .pre_handler = pre_chdir_handler,
};
static struct kprobe kp_unlinkat = {
    .symbol_name = "__arm64_sys_unlinkat",
    .pre_handler = pre_unlinkat_handler,
};
static struct kprobe kp_fstatat = {
    .symbol_name = "__arm64_sys_newfstatat",
    .pre_handler = pre_fstatat_handler,
};

static int __init hma_init(void)
{
    int ret;
    pr_info("[HMAKO]HMAKernelObject ko init\n");
    ret = register_kprobe(&kp_mkdirat);
    if (ret) {
        pr_err("[HMAKO]register_kprobe mkdirat failed: %d\n", ret);
        goto out;
    }
    ret = register_kprobe(&kp_chdir);
    if (ret) {
        pr_err("[HMAKO]register_kprobe chdir failed: %d\n", ret);
        unregister_kprobe(&kp_mkdirat);
        goto out;
    }
    ret = register_kprobe(&kp_unlinkat);
    if (ret) {
        pr_err("[HMAKO]register_kprobe unlinkat failed: %d\n", ret);
        unregister_kprobe(&kp_chdir);
        unregister_kprobe(&kp_mkdirat);
        goto out;
    }
    ret = register_kprobe(&kp_fstatat);
    if (ret) {
        pr_err("[HMAKO]register_kprobe fstatat failed: %d\n", ret);
        unregister_kprobe(&kp_unlinkat);
        unregister_kprobe(&kp_chdir);
        unregister_kprobe(&kp_mkdirat);
        goto out;
    }
    pr_info("[HMAKO]Successfully registered kprobes\n");
out:
    return ret;
}

static void __exit hma_exit(void)
{
    unregister_kprobe(&kp_fstatat);
    unregister_kprobe(&kp_unlinkat);
    unregister_kprobe(&kp_chdir);
    unregister_kprobe(&kp_mkdirat);
    pr_info("[HMAKO]HMAKernelObject ko exit\n");
}

module_init(hma_init);
module_exit(hma_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("baaad");
MODULE_DESCRIPTION("HMAKernelObject");
