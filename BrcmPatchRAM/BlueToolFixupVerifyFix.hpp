//
//  BlueToolFixupVerifyFix.hpp
//  BrcmPatchRAM
//
//  "verify-fix" for BlueToolFixup (AX210 report, section 12 and appendix G), revision 3 (report v10).
//  Keeps bluetoothd from failing with "Data hash mismatch" (EBADMSG, SIGBUS) on macOS 26, where APFS
//  verifies compressed system files in 16 KB blocks that include pages we patched.
//
//  Use: put this file next to BlueToolFixup.cpp and make three small edits there (4 lines in total):
//   1. after  #define MODULE_SHORT "btlfx"
//          #include "BlueToolFixupVerifyFix.hpp"
//   2. first line inside  if (vn_getpath(vp, path, &pathlen) == 0 && ...) {  in patched_cs_validate_page()
//          VerifyFix::PatchRecorder recorder(vp, page_offset, data, path);
//   3. after  SYSLOG(MODULE_SHORT, "failed to route cs validation pages");  in pluginStart()
//          else
//              VerifyFix::init(patcher);
//  The edits are the same as for revisions 1 and 2: if they are already in place, replacing this file is enough.
//
//  Written for the hexxyan/BlueToolFixup-FixA2DP fork (branch fix-a2dp-fastconnect, d8bd62a); the same
//  three edits also apply to acidanthera/BrcmPatchRAM master (4fdd4d4). The file relies only on the Lilu
//  headers, the Kernel.framework headers and MODULE_SHORT, which BlueToolFixup.cpp provides before the include.
//
//  Revision 2 moved layer 1 from the exported VNOP_VERIFY (inlined everywhere on macOS 26, so that route
//  never ran) to the vnop_verify entry of the APFS vnode operation vector, which every inlined copy calls.
//  Revision 3 (review of revision 2, report 12.11) changes only layer 1:
//   - The vnop_verify argument block is declared here (layout of macOS 13 and later). Revision 2 used the
//     SDK's struct vnop_verify_args, but MacKernelSDK is based on the macOS 11 SDK, where a_verify_ctxp
//     probably does not exist yet. The fields used for verifying (a_desc to a_verifyblksize) have not moved
//     since macOS 11; a_verify_ctxp and a_flags only decide whether to take over.
//   - The wrapper only handles argument blocks whose a_desc is vnop_verify_desc; anything else passes on.
//   - Layer 1 is installed from a thread call, no longer inside cs_validate_page. The vector found in the
//     vnode of the patched file must be confirmed by a second system file in another directory (/bin/ls):
//     same position in the vnode, same vector. Every entry up to the vnop_verify slot must be a kernel
//     pointer, and the vnop_verify entry must differ from the default entry.
//   - The entry is replaced with Lilu's kernel write enable (MachInfo::setKernelWriting), so a
//     write-protected vector cannot cause a panic.
//   - sysctl debug.btlfx also shows where v_op was found (voff=) and foreign argument blocks (baddesc=).
//
//  Status: type-checked with g++ against stand-in headers; this environment has no assembler or linker,
//  so the C++ was not run. The logic was run as a step-by-step Python model (report appendix G).
//  NOT compiled with Xcode, NOT tested on macOS.
//

#ifndef BlueToolFixupVerifyFix_hpp
#define BlueToolFixupVerifyFix_hpp

#include <IOKit/IOLocks.h>
#include <kern/clock.h>
#include <kern/thread_call.h>
#include <sys/errno.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>
#include <sys/vnode.h>
#include <sys/vnode_if.h>

#ifndef CTLFLAG_OID2
#define CTLFLAG_OID2 0x00400000
#endif
#ifndef CTLFLAG_LOCKED
#define CTLFLAG_LOCKED 0x00800000
#endif
#ifndef SYSCTL_OID_VERSION
#define SYSCTL_OID_VERSION 1
#endif
#ifndef VERIFYFIX_KERNEL_MIN
#define VERIFYFIX_KERNEL_MIN 0xffffff8000000000ULL   // lowest x86_64 kernel address
#endif

#pragma mark - Verify fix

//
// Why this exists
// ---------------
// patched_cs_validate_page() patches the page that sits in the shared file cache (UBC), so every
// mapping and every read() of /usr/sbin/bluetoothd sees the patched bytes. On x86_64 (4 KB pages),
// APFS verifies compressed files on the sealed system volume in 16 KB blocks. When only part of such
// a block has to be paged in again, decmpfs hashes the whole block, including the pages that are
// still resident. If one of them is a patched page, the hash cannot match: the page-in fails with
// EBADMSG (94), bluetoothd dies with SIGBUS, and it keeps dying for as long as the patched page stays
// resident (in practice until reboot).
//
// Layer 1 (verify): replace the vnop_verify entry of the APFS vnode operation vector. When a block of
//   a tracked file still contains bytes that we patched, verify a private copy of that block in which
//   exactly those bytes are put back to their recorded original values. The live pages are never
//   written, so running threads are unaffected, and any other difference from the sealed data is still
//   detected. Installed from a thread call after the first patch; every other call passes straight on.
// Layer 2 (heal): wrap decmpfs_pagein_compressed. If a page-in of a tracked file still fails with
//   EBADMSG, drop the cached pages of that file from a thread call: first the range of the failed
//   page-in, then the whole file. The next fault pages whole blocks in again (all pages absent, so the
//   hash matches). Measured on 26.7.3 with revision 1: the faulting reader even survived (report 12.10).
//
// Status: sysctl debug.btlfx, for example
//   verifyfix r3 l1=on slot=47 voff=0xd0 l2=on files=1 sites=5 | l1: calls=812 restored=2 restore_failed=0 skipped=0 flags=0x0 baddesc=0 | l2: failed_pageins=0 heals=0 heal_error=0
//
// Boot-args: -btlfxnoverify disables layer 1, -btlfxnoheal disables layer 2.
//

namespace VerifyFix {

static constexpr size_t MaxSites     = 32;
static constexpr size_t MaxSiteBytes = 24;
static constexpr size_t MaxFiles     = 2;
static constexpr size_t MaxVerifyBlk = 64 * 1024;
static constexpr size_t MergeGap     = 8;
// struct vnode is private. Its fields v_op, v_mount and v_data are adjacent in every xnu release (on
// current x86_64 kernels at 0xd0, 0xd8 and 0xe0), and the structure is longer than VnodeScanTo.
static constexpr size_t VnodeScanFrom = 0x40;
static constexpr size_t VnodeScanTo   = 0x100;
static constexpr int    MaxVnopSlot   = 256;
// Second file for confirming the vector: a regular file on the system volume in another directory, so that
// a per-file field such as v_parent cannot pass for v_op.
static const char * const CrossCheckFiles[] = {"/bin/ls", "/bin/sh"};

enum : int {
	L1Off = 0,          // -btlfxnoverify, or no memory
	L1Waiting = 1,      // ready; queued when the first patch is recorded
	L1Queued = 2,       // installation thread call queued
	L1On = 3,           // vnop_verify entry of the APFS vector replaced
	L1NoDesc = -1,      // _vnop_verify_desc not found, not what we expect, or no slot assigned
	L1NoVnode = -2,     // vnode_lookup of the patched file failed
	L1NotApfs = -3,     // the patched file is not on APFS
	L1NoOpVector = -4,  // v_mount/v_data pair not found in the vnode
	L1CrossCheck = -5,  // no second file showed the same vector at the same position
	L1BadVector = -6,   // the vector does not look like a vnode operation vector
	L1WriteFailed = -7, // kernel write enable failed
	L1Raced = -8,       // the entry changed while we replaced it
};

struct Site {
	vnode_t  vp;      // identity only, never dereferenced
	uint32_t vid;
	uint32_t len;
	uint64_t off;     // offset in the file (= offset in the vnode's memory object)
	uint8_t  orig[MaxSiteBytes];
	uint8_t  patched[MaxSiteBytes];
};

struct File {
	vnode_t  vp;
	uint32_t vid;
	bool     healPending;
	uint64_t healFrom, healTo;   // byte range of the last failed page-in
	char     path[32];
};

struct Counters {
	uint32_t verifyCalls;     // vnop_verify calls with data of a tracked file
	uint32_t restored;        // blocks verified from a copy with the original bytes: passed
	uint32_t restoreFailed;   // ... and failed anyway (real damage, or bytes we did not record)
	uint32_t skipped;         // calls with a verify context or flags: passed on unchanged
	uint32_t lastSkipFlags;
	uint32_t badDesc;         // calls whose argument block is not vnop_verify's (counts up to 1000)
	uint32_t pageinFailed;    // page-ins of a tracked file that returned EBADMSG
	uint32_t heals;           // heal runs
	int32_t  healError;       // result of the last heal run
};

// Argument block of vnop_verify on macOS 13 and later: VNOP_VERIFY() (bsd/vfs/kpi_vfs.c) fills it and calls
// vp->v_op[vnop_verify_desc.vdesc_offset](&a). Declared here instead of taken from the SDK, because
// MacKernelSDK is based on the macOS 11 SDK. a_desc .. a_verifyblksize have the same offsets since macOS 11.
// a_verify_ctxp and a_flags are only read to decide whether to take over; with another layout at 0x30/0x38
// (for example macOS 11, where a_flags sits at 0x30) the wrapper passes the call on unchanged. Fields after
// a_context, if a later release adds any, are never touched: the caller's block is reused.
struct VerifyArgs {
	void          *a_desc;
	vnode_t        a_vp;
	off_t          a_foffset;
	uint8_t       *a_buf;
	size_t         a_bufsize;
	size_t        *a_verifyblksize;
	void         **a_verify_ctxp;
	int            a_flags;
	vfs_context_t  a_context;
};
static_assert(__builtin_offsetof(VerifyArgs, a_vp) == 0x08 && __builtin_offsetof(VerifyArgs, a_buf) == 0x18 &&
			  __builtin_offsetof(VerifyArgs, a_verifyblksize) == 0x28 && __builtin_offsetof(VerifyArgs, a_verify_ctxp) == 0x30 &&
			  __builtin_offsetof(VerifyArgs, a_flags) == 0x38 && __builtin_offsetof(VerifyArgs, a_context) == 0x40,
			  "unexpected layout of the vnop_verify argument block");

using VerifyOp = int (*)(void *);

static Site sites[MaxSites];
static size_t siteCount;
static File files[MaxFiles];
static size_t fileCount;           // published with release stores, read without the lock
static IOLock *lock;               // sites, files, snapshot
static IOLock *scratchLock;        // scratch
static uint8_t snapshot[PAGE_SIZE];
static uint8_t scratch[MaxVerifyBlk] __attribute__((aligned(4096)));
static thread_call_t healCall, statusCall, installCall;
static bool tracking, healOn, firstCallLogged, statusRegistered, installStarted;
static int l1State;
static const void *verifyDesc;     // &vnop_verify_desc (struct vnodeop_desc)
static int verifySlot = -1;
static int vopOffset = -1;         // byte offset of v_op in struct vnode, as found
static VerifyOp orgVerifyOp;
static mach_vm_address_t orgPagein, sysctlParent, sysctlRegister;
static Counters counters;
static struct sysctl_oid statusOid;

static inline void bump(uint32_t &c) {
	__atomic_fetch_add(&c, 1, __ATOMIC_RELAXED);
}

// Hot path (every vnop_verify on APFS, every compressed page-in): pointer compares only;
// vnode_vid() is called only for a pointer that matches, on a vnode the caller holds.
static bool lookupFile(vnode_t vp, size_t *index) {
	size_t n = __atomic_load_n(&fileCount, __ATOMIC_ACQUIRE);
	for (size_t i = 0; i < n; i++) {
		if (files[i].vp == vp && files[i].vid == static_cast<uint32_t>(vnode_vid(vp))) {
			if (index) *index = i;
			return true;
		}
	}
	return false;
}

static void registerFileLocked(vnode_t vp, uint32_t vid, const char *path) {
	for (size_t i = 0; i < fileCount; i++) {
		if (strcmp(files[i].path, path) == 0) {
			files[i].vid = vid;   // the vnode may have been recycled and looked up again
			files[i].vp = vp;
			return;
		}
	}
	if (fileCount < MaxFiles) {
		File &f = files[fileCount];
		f.vp = vp;
		f.vid = vid;
		f.healPending = false;
		f.healFrom = f.healTo = 0;
		strlcpy(f.path, path, sizeof(f.path));
		__atomic_store_n(&fileCount, fileCount + 1, __ATOMIC_RELEASE);
	}
}

static bool siteIsCurrentLocked(const Site &s) {
	for (size_t i = 0; i < fileCount; i++)
		if (files[i].vp == s.vp && files[i].vid == s.vid)
			return true;
	return false;
}

static void addSiteLocked(vnode_t vp, uint32_t vid, uint64_t off, const uint8_t *orig, const uint8_t *patched, size_t len) {
	for (size_t i = 0; i < siteCount; i++) {
		const Site &s = sites[i];
		if (s.vp == vp && s.vid == vid && s.off == off && s.len == len)
			return;   // the page was paged in again and re-patched: already known
	}
	Site *s = nullptr;
	if (siteCount < MaxSites) {
		s = &sites[siteCount++];
	} else {
		for (size_t i = 0; i < siteCount && s == nullptr; i++)
			if (!siteIsCurrentLocked(sites[i]))
				s = &sites[i];   // reuse a slot of an old vnode generation
	}
	if (s == nullptr) {
		SYSLOG(MODULE_SHORT, "verify-fix: site table full, 0x%llx not recorded", off);
		return;
	}
	s->vp = vp;
	s->vid = vid;
	s->off = off;
	s->len = static_cast<uint32_t>(len);
	memcpy(s->orig, orig, len);
	memcpy(s->patched, patched, len);
	SYSLOG(MODULE_SHORT, "verify-fix: recorded patch site 0x%llx (%lu bytes)", off, static_cast<unsigned long>(len));
}

// Compare the page before and after our patches and remember every changed byte run, so that the
// exact original bytes can be put back later. Works for any current or future patch in this file.
static void recordLocked(vnode_t vp, const char *path, uint64_t pageOff, const uint8_t *before, const uint8_t *after) {
	uint32_t vid = static_cast<uint32_t>(vnode_vid(vp));
	bool registered = false;
	for (size_t i = 0; i < PAGE_SIZE; ) {
		if (before[i] == after[i]) {
			i++;
			continue;
		}
		size_t start = i, last = i;
		for (size_t j = i + 1; j < PAGE_SIZE && j - start < MaxSiteBytes; j++) {
			if (before[j] != after[j])
				last = j;
			else if (j - last > MergeGap)
				break;
		}
		if (!registered) {
			registerFileLocked(vp, vid, path);
			registered = true;
		}
		addSiteLocked(vp, vid, pageOff + start, before + start, after + start, last - start + 1);
		i = last + 1;
	}
}

// Sites never cross a 4 KB page, so they never cross a verify block either.
static bool siteInRange(const Site &s, vnode_t vp, uint32_t vid, uint64_t foff, size_t len) {
	return s.vp == vp && s.vid == vid && s.off >= foff && s.off + s.len <= foff + len;
}

static size_t countPatchedLocked(vnode_t vp, uint32_t vid, uint64_t foff, const uint8_t *buf, size_t len) {
	size_t n = 0;
	for (size_t i = 0; i < siteCount; i++) {
		const Site &s = sites[i];
		if (siteInRange(s, vp, vid, foff, len) && memcmp(buf + (s.off - foff), s.patched, s.len) == 0)
			n++;
	}
	return n;
}

static size_t restoreLocked(vnode_t vp, uint32_t vid, uint64_t foff, uint8_t *buf, size_t len) {
	size_t bytes = 0;
	for (size_t i = 0; i < siteCount; i++) {
		const Site &s = sites[i];
		if (siteInRange(s, vp, vid, foff, len) && memcmp(buf + (s.off - foff), s.patched, s.len) == 0) {
			memcpy(buf + (s.off - foff), s.orig, s.len);
			bytes += s.len;
		}
	}
	return bytes;
}

// callOrg(foff, buf, size, &verifyBlockSize) calls the original verifier with the other arguments
// unchanged. Clean runs of blocks are verified in place; each block that still holds patched bytes
// is verified from a copy with those bytes restored.
template <typename F>
static errno_t verifyTracked(vnode_t vp, off_t foff, uint8_t *buf, size_t bufsize, size_t *vbsp, F callOrg) {
	size_t vbs = *vbsp;
	if (foff < 0 || vbs == 0 || vbs > MaxVerifyBlk || (vbs & (vbs - 1)) != 0 || (static_cast<uint64_t>(foff) & (vbs - 1)) != 0)
		return callOrg(foff, buf, bufsize, vbsp);

	uint32_t vid = static_cast<uint32_t>(vnode_vid(vp));
	IOLockLock(lock);
	size_t dirty = countPatchedLocked(vp, vid, static_cast<uint64_t>(foff), buf, bufsize);
	IOLockUnlock(lock);
	if (dirty == 0)
		return callOrg(foff, buf, bufsize, vbsp);

	errno_t err = 0;
	size_t off = 0, clean = 0;   // [clean, off) is a run of blocks without patched bytes
	while (off < bufsize && err == 0) {
		size_t len = bufsize - off < vbs ? bufsize - off : vbs;
		IOLockLock(lock);
		bool blockDirty = countPatchedLocked(vp, vid, static_cast<uint64_t>(foff) + off, buf + off, len) != 0;
		IOLockUnlock(lock);
		if (blockDirty) {
			if (off > clean) {
				size_t v = vbs;
				err = callOrg(foff + static_cast<off_t>(clean), buf + clean, off - clean, &v);
				if (err != 0)
					break;
			}
			IOLockLock(scratchLock);
			memcpy(scratch, buf + off, len);
			IOLockLock(lock);
			size_t restored = restoreLocked(vp, vid, static_cast<uint64_t>(foff) + off, scratch, len);
			IOLockUnlock(lock);
			size_t v = vbs;
			err = callOrg(foff + static_cast<off_t>(off), scratch, len, &v);
			IOLockUnlock(scratchLock);
			bump(err == 0 ? counters.restored : counters.restoreFailed);
			SYSLOG(MODULE_SHORT, "verify-fix: block 0x%llx verified with %lu original byte(s) restored, error %d",
				   static_cast<uint64_t>(foff) + off, static_cast<unsigned long>(restored), err);
			clean = off + len;
		}
		off += len;
	}
	if (err == 0 && clean < bufsize) {
		size_t v = vbs;
		err = callOrg(foff + static_cast<off_t>(clean), buf + clean, bufsize - clean, &v);
	}
	return err;
}

//
// Layer 1: the vnop_verify entry of the APFS vnode operation vector.
//
// The kernel's VNOP_VERIFY() (inlined or not) fills the argument block and calls
// vp->v_op[vnop_verify_desc.vdesc_offset](&args). We take over only for vnop_verify's argument block, a
// tracked file, a buffer to verify, no verify context and no flags: that is how decmpfs verifies a page-in.
// Anything else is passed on unchanged (and counted as skipped when it concerns a tracked file).
//
static int wrapVerifyOp(void *arg) {
	auto ap = static_cast<VerifyArgs *>(arg);
	const VerifyOp org = orgVerifyOp;
	if (UNLIKELY(ap->a_desc != verifyDesc)) {
		if (__atomic_load_n(&counters.badDesc, __ATOMIC_RELAXED) < 1000)
			bump(counters.badDesc);
		return org(arg);
	}
	if (LIKELY(ap->a_buf == nullptr || ap->a_bufsize == 0 || ap->a_verifyblksize == nullptr || !lookupFile(ap->a_vp, nullptr)))
		return org(arg);
	bump(counters.verifyCalls);
	const uint32_t flags = static_cast<uint32_t>(ap->a_flags);
	if (!__atomic_exchange_n(&firstCallLogged, true, __ATOMIC_RELAXED))
		SYSLOG(MODULE_SHORT, "verify-fix: first vnop_verify of a tracked file (0x%llx, %lu bytes, block %lu, flags 0x%x, context %s)",
			   static_cast<uint64_t>(ap->a_foffset), static_cast<unsigned long>(ap->a_bufsize),
			   static_cast<unsigned long>(*ap->a_verifyblksize), flags, ap->a_verify_ctxp ? "yes" : "no");
	if (ap->a_verify_ctxp != nullptr || flags != 0) {
		bump(counters.skipped);
		__atomic_store_n(&counters.lastSkipFlags, flags, __ATOMIC_RELAXED);
		return org(arg);
	}
	return verifyTracked(ap->a_vp, ap->a_foffset, ap->a_buf, ap->a_bufsize, ap->a_verifyblksize,
						 [ap, org](off_t o, uint8_t *b, size_t s, size_t *v) -> errno_t {
		// Same argument block, with the range (and the block-size pointer) of this piece; restored afterwards.
		const auto saveOff = ap->a_foffset;
		const auto saveBuf = ap->a_buf;
		const auto saveSize = ap->a_bufsize;
		const auto saveVbs = ap->a_verifyblksize;
		ap->a_foffset = o;
		ap->a_buf = b;
		ap->a_bufsize = s;
		ap->a_verifyblksize = v;
		errno_t r = org(ap);
		ap->a_foffset = saveOff;
		ap->a_buf = saveBuf;
		ap->a_bufsize = saveSize;
		ap->a_verifyblksize = saveVbs;
		return r;
	});
}

static bool kernelPointer(const void *p) {
	return reinterpret_cast<uintptr_t>(p) >= VERIFYFIX_KERNEL_MIN;
}

// struct vnode is private, but its fields v_op, v_mount and v_data are adjacent, and the KPI returns the
// last two. Returns the word index of v_mount (so v_op is the word before it), or -1.
static int findMountWord(vnode_t vp) {
	const uintptr_t mp = reinterpret_cast<uintptr_t>(vnode_mount(vp));
	const uintptr_t fsnode = reinterpret_cast<uintptr_t>(vnode_fsnode(vp));
	if (mp == 0 || fsnode == 0)
		return -1;
	auto words = reinterpret_cast<const uintptr_t *>(vp);
	for (size_t i = VnodeScanFrom / sizeof(uintptr_t); (i + 2) * sizeof(uintptr_t) <= VnodeScanTo; i++)
		if (words[i] == mp && words[i + 1] == fsnode)
			return static_cast<int>(i);
	return -1;
}

static uintptr_t wordAt(vnode_t vp, int index) {
	return reinterpret_cast<const uintptr_t *>(vp)[index];
}

static bool onApfs(vnode_t vp) {
	mount_t mp = vnode_mount(vp);
	struct vfsstatfs *st = mp ? vfs_statfs(mp) : nullptr;
	return st != nullptr && strncmp(st->f_fstypename, "apfs", sizeof("apfs")) == 0;
}

// Runs once on a thread-call thread, queued by the recorder of the first patched page (bluetoothd runs, so
// vfs_op_init() has assigned the slots long ago). Nothing here runs in the page-fault path.
static void installCallback(thread_call_param_t, thread_call_param_t) {
	if (__atomic_load_n(&l1State, __ATOMIC_ACQUIRE) != L1Queued || __atomic_exchange_n(&installStarted, true, __ATOMIC_ACQ_REL))
		return;
	int state = L1On;
	int word = -1;
	void **vec = nullptr;
	const int slot = *static_cast<const volatile int *>(verifyDesc);   // vdesc_offset
	vfs_context_t ctx = vfs_context_create(nullptr);
	vnode_t vp = NULLVP;
	if (slot <= 0 || slot >= MaxVnopSlot) {
		state = L1NoDesc;
	} else if (vnode_lookup(files[0].path, 0, &vp, ctx) != 0) {
		vp = NULLVP;
		state = L1NoVnode;
	} else if (!onApfs(vp)) {
		state = L1NotApfs;
	} else if ((word = findMountWord(vp)) < 1) {
		state = L1NoOpVector;
	} else {
		vec = reinterpret_cast<void **>(wordAt(vp, word - 1));
		bool confirmed = false;
		for (size_t i = 0; i < arrsize(CrossCheckFiles) && !confirmed; i++) {
			vnode_t other = NULLVP;
			if (vnode_lookup(CrossCheckFiles[i], 0, &other, ctx) != 0)
				continue;
			confirmed = other != vp && onApfs(other) && findMountWord(other) == word &&
						wordAt(other, word - 1) == reinterpret_cast<uintptr_t>(vec);
			vnode_put(other);
		}
		if (!confirmed)
			state = L1CrossCheck;
	}
	if (state == L1On) {
		// Every entry of a vnode operation vector is set (vfs_fsadd fills empty ones with the default), and
		// APFS implements vnop_verify, so its entry is not the default one.
		bool plausible = kernelPointer(vec);
		for (int i = 0; plausible && i <= slot; i++)
			plausible = kernelPointer(vec[i]);
		void *cur = plausible ? __atomic_load_n(&vec[slot], __ATOMIC_ACQUIRE) : nullptr;
		void *wrapper = reinterpret_cast<void *>(&wrapVerifyOp);
		if (!plausible || cur == vec[0] || cur == wrapper) {
			state = L1BadVector;
		} else {
			orgVerifyOp = reinterpret_cast<VerifyOp>(cur);   // visible before the entry points to the wrapper
			if (MachInfo::setKernelWriting(true, KernelPatcher::kernelWriteLock) != KERN_SUCCESS) {
				state = L1WriteFailed;
			} else {
				const bool swapped = __atomic_compare_exchange_n(&vec[slot], &cur, wrapper, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
				MachInfo::setKernelWriting(false, KernelPatcher::kernelWriteLock);
				if (!swapped)
					state = L1Raced;
			}
		}
	}
	if (vp != NULLVP)
		vnode_put(vp);
	vfs_context_rele(ctx);
	if (state == L1On) {
		verifySlot = slot;
		vopOffset = (word - 1) * static_cast<int>(sizeof(uintptr_t));
		SYSLOG(MODULE_SHORT, "verify-fix: layer 1 on: vnop_verify of APFS hooked (vector %p, slot %d, v_op at 0x%x)",
			   static_cast<void *>(vec), slot, vopOffset);
	} else {
		SYSLOG(MODULE_SHORT, "verify-fix: layer 1 NOT installed (state %d, slot %d, v_mount word %d)", state, slot, word);
	}
	__atomic_store_n(&l1State, state, __ATOMIC_RELEASE);
}

//
// Layer 2: self-heal.
//
static void healCallback(thread_call_param_t, thread_call_param_t) {
	size_t n = __atomic_load_n(&fileCount, __ATOMIC_ACQUIRE);
	for (size_t i = 0; i < n; i++) {
		if (!__atomic_exchange_n(&files[i].healPending, false, __ATOMIC_ACQ_REL))
			continue;
		const uint64_t from = __atomic_load_n(&files[i].healFrom, __ATOMIC_RELAXED);
		const uint64_t to = __atomic_load_n(&files[i].healTo, __ATOMIC_RELAXED);
		vfs_context_t ctx = vfs_context_create(nullptr);
		vnode_t vp = NULLVP;
		errno_t err = vnode_lookup(files[i].path, 0, &vp, ctx);
		if (err == 0) {
			// The failed range first: it is reached at once, so its pages are freed as soon as the failed
			// page-in lets go of them. Then the whole file, for any other block in the same state.
			// Clean, unwired pages are unmapped and freed; pages wired by mlock (vmtouch -l) stay.
			errno_t first = to > from ? ubc_msync(vp, static_cast<off_t>(from), static_cast<off_t>(to), nullptr, UBC_INVALIDATE) : 0;
			err = ubc_msync(vp, 0, ubc_getsize(vp), nullptr, UBC_INVALIDATE);
			if (err == 0)
				err = first;
			vnode_put(vp);
		}
		vfs_context_rele(ctx);
		bump(counters.heals);
		__atomic_store_n(&counters.healError, static_cast<int32_t>(err), __ATOMIC_RELAXED);
		SYSLOG(MODULE_SHORT, "self-heal: dropped cached pages of %s (0x%llx-0x%llx first), result %d", files[i].path, from, to, err);
	}
}

static int wrapPagein(struct vnop_pagein_args *ap, int *isCompressed, void *cp) {
	int err = FunctionCast(wrapPagein, orgPagein)(ap, isCompressed, cp);
	size_t i = 0;
	if (UNLIKELY(err == EBADMSG) && healOn && ap != nullptr && lookupFile(ap->a_vp, &i)) {
		bump(counters.pageinFailed);
		SYSLOG(MODULE_SHORT, "self-heal: page-in of %s at 0x%llx failed with EBADMSG, dropping its cached pages",
			   files[i].path, static_cast<uint64_t>(ap->a_f_offset));
		__atomic_store_n(&files[i].healFrom, static_cast<uint64_t>(ap->a_f_offset), __ATOMIC_RELAXED);
		__atomic_store_n(&files[i].healTo, static_cast<uint64_t>(ap->a_f_offset) + ap->a_size, __ATOMIC_RELAXED);
		__atomic_store_n(&files[i].healPending, true, __ATOMIC_RELEASE);
		thread_call_enter(healCall);
	}
	return err;
}

//
// Status: sysctl debug.btlfx (read-only string).
//
static const char *l1Name(int s) {
	switch (s) {
		case L1Off:         return "off";
		case L1Waiting:     return "waiting";
		case L1Queued:      return "queued";
		case L1On:          return "on";
		case L1NoDesc:      return "fail-desc";
		case L1NoVnode:     return "fail-novnode";
		case L1NotApfs:     return "fail-notapfs";
		case L1NoOpVector:  return "fail-vnode";
		case L1CrossCheck:  return "fail-xcheck";
		case L1BadVector:   return "fail-vector";
		case L1WriteFailed: return "fail-write";
		case L1Raced:       return "fail-raced";
		default:            return "unknown";
	}
}

static int statusSysctl(struct sysctl_oid *, void *, int, struct sysctl_req *req) {
	char buf[360];
	char voff[16];
	if (vopOffset >= 0)
		snprintf(voff, sizeof(voff), "0x%x", vopOffset);
	else
		strlcpy(voff, "none", sizeof(voff));
	snprintf(buf, sizeof(buf),
			 "verifyfix r3 l1=%s slot=%d voff=%s l2=%s files=%lu sites=%lu | l1: calls=%u restored=%u restore_failed=%u skipped=%u"
			 " flags=0x%x baddesc=%u | l2: failed_pageins=%u heals=%u heal_error=%d",
			 l1Name(__atomic_load_n(&l1State, __ATOMIC_ACQUIRE)), verifySlot, voff, healOn ? "on" : "off",
			 static_cast<unsigned long>(__atomic_load_n(&fileCount, __ATOMIC_ACQUIRE)),
			 static_cast<unsigned long>(__atomic_load_n(&siteCount, __ATOMIC_RELAXED)),
			 __atomic_load_n(&counters.verifyCalls, __ATOMIC_RELAXED), __atomic_load_n(&counters.restored, __ATOMIC_RELAXED),
			 __atomic_load_n(&counters.restoreFailed, __ATOMIC_RELAXED), __atomic_load_n(&counters.skipped, __ATOMIC_RELAXED),
			 __atomic_load_n(&counters.lastSkipFlags, __ATOMIC_RELAXED), __atomic_load_n(&counters.badDesc, __ATOMIC_RELAXED),
			 __atomic_load_n(&counters.pageinFailed, __ATOMIC_RELAXED),
			 __atomic_load_n(&counters.heals, __ATOMIC_RELAXED), __atomic_load_n(&counters.healError, __ATOMIC_RELAXED));
	return SYSCTL_OUT(req, buf, strlen(buf) + 1);
}

// Runs once, 30 s after init on a thread-call thread (BSD is up by then). The parent node and the
// register function are looked up through Lilu, so the kext gains no new link-time dependency.
static void statusCallback(thread_call_param_t, thread_call_param_t) {
	if (sysctlParent == 0 || sysctlRegister == 0 || __atomic_exchange_n(&statusRegistered, true, __ATOMIC_ACQ_REL))
		return;
	statusOid.oid_parent = reinterpret_cast<struct sysctl_oid_list *>(sysctlParent);
	statusOid.oid_number = OID_AUTO;
	statusOid.oid_kind = static_cast<int>(CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_OID2);
	statusOid.oid_arg1 = nullptr;
	statusOid.oid_arg2 = 0;
	statusOid.oid_name = const_cast<char *>("btlfx");
	statusOid.oid_handler = statusSysctl;
	statusOid.oid_fmt = const_cast<char *>("A");
	statusOid.oid_descr = const_cast<char *>("BlueToolFixup verify-fix status");
	statusOid.oid_version = SYSCTL_OID_VERSION;
	reinterpret_cast<void (*)(struct sysctl_oid *)>(sysctlRegister)(&statusOid);
	SYSLOG(MODULE_SHORT, "verify-fix: status available as sysctl debug.btlfx");
}

static void init(KernelPatcher &patcher) {
	bool wantVerify = !checkKernelArgument("-btlfxnoverify");
	bool wantHeal = !checkKernelArgument("-btlfxnoheal");

	sysctlParent = patcher.solveSymbol(KernelPatcher::KernelID, "_sysctl__debug_children");
	sysctlRegister = sysctlParent ? patcher.solveSymbol(KernelPatcher::KernelID, "_sysctl_register_oid") : 0;
	if (sysctlRegister == 0)
		patcher.clearError();
	statusCall = thread_call_allocate(statusCallback, nullptr);
	if (statusCall != nullptr) {
		uint64_t deadline = 0;
		clock_interval_to_deadline(30, 1000 * 1000 * 1000, &deadline);
		thread_call_enter_delayed(statusCall, deadline);
	}

	if (wantVerify || wantHeal) {
		lock = IOLockAlloc();
		scratchLock = IOLockAlloc();
		healCall = thread_call_allocate(healCallback, nullptr);
		installCall = thread_call_allocate(installCallback, nullptr);
		if (lock == nullptr || scratchLock == nullptr || healCall == nullptr || installCall == nullptr) {
			SYSLOG(MODULE_SHORT, "verify-fix: allocation failed, disabled");
			wantVerify = wantHeal = false;
		}
	}

	if (wantHeal) {
		KernelPatcher::RouteRequest req("_decmpfs_pagein_compressed", wrapPagein, orgPagein);
		healOn = patcher.routeMultipleLong(KernelPatcher::KernelID, &req, 1);
		if (!healOn)
			patcher.clearError();
	}

	if (wantVerify) {
		// Only the descriptor is checked here. Its slot (vdesc_offset) is read at installation time,
		// because the kernel assigns the slots in vfs_op_init(), which may run after this plugin starts.
		mach_vm_address_t desc = patcher.solveSymbol(KernelPatcher::KernelID, "_vnop_verify_desc");
		if (desc == 0)
			patcher.clearError();
		const char *name = desc ? *reinterpret_cast<const char * const *>(desc + sizeof(void *)) : nullptr;   // vdesc_name
		if (name != nullptr && kernelPointer(name) && strcmp(name, "vnop_verify") == 0) {
			verifyDesc = reinterpret_cast<const void *>(desc);
			l1State = L1Waiting;
		} else {
			l1State = L1NoDesc;
		}
	}

	tracking = healOn || l1State == L1Waiting;
	SYSLOG(MODULE_SHORT, "verify-fix r3: layer 1 %s, layer 2 %s, status sysctl %s", l1Name(l1State), healOn ? "on" : "off",
		   sysctlRegister ? "in 30 s" : "unavailable");
}

//
// Patch recorder: the only hook into the patch code. One line in patched_cs_validate_page(),
// right after its "/usr/sbin/" path check:
//
//     VerifyFix::PatchRecorder recorder(vp, page_offset, data, path);
//
// For bluetoothd and BlueTool it copies the page before the patches run. When it goes out of scope,
// after the last patch of that page, it records every byte run that the patches changed. So every
// patch in BlueToolFixup.cpp is covered, including patches added later (for example the Fast-Connect
// A2DP gate of the BlueToolFixup-FixA2DP fork), without changing any patch code. The first time a
// patch is recorded, it queues the installation of layer 1 (installCallback).
//
class PatchRecorder {
	vnode_t mVnode;
	uint64_t mOffset;
	const uint8_t *mPage;
	const char *mPath;
	bool mActive {false};

public:
	PatchRecorder(vnode_t vp, memory_object_offset_t pageOffset, const void *data, const char *path)
		: mVnode(vp), mOffset(pageOffset), mPage(static_cast<const uint8_t *>(data)), mPath(path) {
		static constexpr size_t dirLength = sizeof("/usr/sbin/") - 1;
		if (!tracking || mPage == nullptr || path == nullptr || strncmp(path, "/usr/sbin/", dirLength) != 0)
			return;
		const char *name = path + dirLength;
		if (strcmp(name, "bluetoothd") != 0 && strcmp(name, "BlueTool") != 0)
			return;
		mActive = true;
		IOLockLock(lock);
		memcpy(snapshot, mPage, PAGE_SIZE);
	}

	~PatchRecorder() {
		if (!mActive)
			return;
		recordLocked(mVnode, mPath, mOffset, snapshot, mPage);
		if (__atomic_load_n(&l1State, __ATOMIC_ACQUIRE) == L1Waiting && lookupFile(mVnode, nullptr)) {
			__atomic_store_n(&l1State, L1Queued, __ATOMIC_RELEASE);
			thread_call_enter(installCall);
		}
		IOLockUnlock(lock);
	}

	PatchRecorder(const PatchRecorder &) = delete;
	PatchRecorder &operator=(const PatchRecorder &) = delete;
};

} // namespace VerifyFix

#endif /* BlueToolFixupVerifyFix_hpp */
