# Security Analysis: Hadoop Unpacking Functions

## Executive Summary

This document analyzes the security of Hadoop's file unpacking functions for path traversal, symlink attacks, and other vulnerabilities that could allow writing outside the destination directory.

**Overall Assessment:**
- ✅ **RunJar.unJar()**: SECURE
- ⚠️ **FileUtil.unZip()**: SAFE IN PRACTICE (but incomplete symlink handling)
- ✅ **FileUtil.unTar() - Java Implementation**: SECURE
- ⚠️ **FileUtil.unTar() - Native tar**: SECURITY DEPENDS ON TAR VERSION

---

## 1. RunJar.unJar() Analysis

**File:** `hadoop-common-project/hadoop-common/src/main/java/org/apache/hadoop/util/RunJar.java`

### Implementation Details

Two variants exist:
1. `unJar(InputStream, File, Pattern)` - lines 128-161
2. `unJar(File, File, Pattern)` - lines 200-231

### Security Controls

**Path Traversal Protection** (lines 140-143, 212-215):
```java
String targetDirPath = toDir.getCanonicalPath() + File.separator;
File file = new File(toDir, entry.getName());
if (!file.getCanonicalPath().startsWith(targetDirPath)) {
    throw new IOException("expanding " + entry.getName()
        + " would create file outside of " + toDir);
}
```

**How it works:**
1. Gets canonical path of destination directory with trailing separator
2. Constructs file path by joining destination + entry name
3. Canonicalizes the result (resolves `..`, `.`, symlinks)
4. Checks if canonical path starts with destination directory path
5. Throws exception if entry would escape the destination

**Attack Scenarios Tested:**

| Attack Vector | Entry Name | Result |
|---------------|------------|--------|
| Parent traversal | `../../etc/passwd` | ✅ BLOCKED |
| Absolute path | `/etc/passwd` | ✅ BLOCKED |
| Current dir | `.` | ✅ BLOCKED |
| Mixed | `./../../etc/passwd` | ✅ BLOCKED |

**Symlinks:** JAR files do not support symlinks, so this attack vector does not apply.

**Verdict:** ✅ **SECURE** - Robust path traversal protection.

---

## 2. FileUtil.unZip() Analysis

**File:** `hadoop-common-project/hadoop-common/src/main/java/org/apache/hadoop/fs/FileUtil.java`

### Implementation Details

Two variants exist:
1. `unZip(InputStream, File)` - lines 739-775
2. `unZip(File, File)` - lines 827-871

### Security Controls

**Path Traversal Protection** (lines 749-752, 840-843):
```java
String targetDirPath = toDir.getCanonicalPath() + File.separator;
File file = new File(toDir, entry.getName());
if (!file.getCanonicalPath().startsWith(targetDirPath)) {
    throw new IOException("expanding " + entry.getName()
        + " would create file outside of " + toDir);
}
```

**Permission Preservation** (lines 765-767, 860-862):
```java
if (entry.getPlatform() == ZipArchiveEntry.PLATFORM_UNIX) {
    Files.setPosixFilePermissions(file.toPath(),
        permissionsFromMode(entry.getUnixMode()));
}
```

### Vulnerability Analysis

**Path Traversal:** ✅ Protected (same mechanism as unJar)

**Symlink Handling:** ⚠️ **INCOMPLETE**

The code:
1. Does NOT check if an entry is a symlink
2. Does NOT validate symlink targets
3. Extracts all entries as regular files

**Critical Question:** Does Apache Commons Compress create actual symlinks?

**Investigation Results:**

ZIP files CAN contain symlinks on Unix systems:
- Symlinks are indicated by Unix mode bits: `(mode & 0170000) == 0120000`
- The entry data contains the symlink target path as bytes

**Current Behavior:**
When extracting a symlink entry, the code:
```java
try (OutputStream out = Files.newOutputStream(file.toPath())) {
    IOUtils.copyBytes(zip, out, BUFFER_SIZE);
}
```

This creates a **regular file** containing the symlink target path as data, NOT an actual symlink.

**Why is this safe?**
- `Files.newOutputStream()` creates a regular file
- Even if Unix permissions are set afterward with `Files.setPosixFilePermissions()`, this only changes permissions, not file type
- Symlinks are NOT created on the filesystem

**Proof of Concept Results:**

Python PoC created three malicious ZIP files:

1. **Symlink Escape:** Entry marked as symlink pointing to `../../etc`
   - Result: Regular file created containing "../../etc" as text
   - No actual symlink created ✅

2. **Direct Path Traversal:** Entry named `../../etc/passwd`
   - Result: Blocked by canonical path check ✅

3. **Symlink + Traversal:** Symlink to internal dir + file traversing through it
   - Result: Symlink not created, traversal blocked ✅

**Tested with Hadoop:**

The test file `TestFileUtil.java` includes:
```java
// Lines 879-895
ZipArchiveEntry ze = new ZipArchiveEntry("../foo");
// ...
try {
    FileUtil.unZip(simpleZip, tmp);
    fail("unZip should throw IOException.");
} catch (IOException e) {
    GenericTestUtils.assertExceptionContains(
        "would create file outside of", e);
}
```

This confirms path traversal protection works.

**Verdict:** ✅ **SAFE IN PRACTICE**
- Path traversal attacks: Blocked
- Symlink attacks: Safe by accident (symlinks not created)
- However, symlink handling is incomplete and inconsistent with unTar

**Recommendation:**
Add explicit symlink detection and validation similar to `unTar()`:

```java
// After line 747 (and 836 for File version)
if (!entry.isDirectory()) {
    File file = new File(toDir, entry.getName());
    if (!file.getCanonicalPath().startsWith(targetDirPath)) {
        throw new IOException("expanding " + entry.getName()
            + " would create file outside of " + toDir);
    }

    // ADD THIS: Check if entry is a symlink
    int mode = entry.getUnixMode();
    boolean isSymlink = (mode & 0120000) == 0120000; // S_IFLNK

    if (isSymlink) {
        // Read symlink target
        byte[] targetBytes = new byte[(int)entry.getSize()];
        zip.read(targetBytes);
        String linkTarget = new String(targetBytes, StandardCharsets.UTF_8);

        // Validate symlink target
        String canonicalTarget = getCanonicalPath(linkTarget, toDir);
        if (!canonicalTarget.startsWith(targetDirPath)) {
            throw new IOException("expanding symlink " + entry.getName()
                + " would create link outside of " + toDir);
        }

        // Create actual symlink
        Files.createSymbolicLink(file.toPath(),
            Paths.get(canonicalTarget));
        continue;
    }

    // ... existing file extraction code
}
```

---

## 3. FileUtil.unTar() - Java Implementation

**File:** `hadoop-common-project/hadoop-common/src/main/java/org/apache/hadoop/fs/FileUtil.java`

### Implementation Details

Main entry points:
- `unTar(File, File)` - lines 1015-1033
- `unTar(InputStream, File, boolean)` - lines 985-1003
- `unTarUsingJava(File, File, boolean)` - lines 1086-1109
- `unpackEntries(TarArchiveInputStream, TarArchiveEntry, File)` - lines 1130-1186

Used on:
- Windows (always)
- Unix/Linux (when native tar is not available or for testing)

### Security Controls

The `unpackEntries()` method implements comprehensive security:

**1. Path Traversal Protection** (lines 1132-1137):
```java
String targetDirPath = outputDir.getCanonicalPath() + File.separator;
File outputFile = new File(outputDir, entry.getName());
if (!outputFile.getCanonicalPath().startsWith(targetDirPath)) {
    throw new IOException("expanding " + entry.getName()
        + " would create entry outside of " + outputDir);
}
```

**2. Symlink Target Validation** (lines 1139-1145):
```java
if (entry.isSymbolicLink() || entry.isLink()) {
    String canonicalTargetPath = getCanonicalPath(entry.getLinkName(), outputDir);
    if (!canonicalTargetPath.startsWith(targetDirPath)) {
        throw new IOException(
            "expanding " + entry.getName() + " would create entry outside of " + outputDir);
    }
}
```

**3. Safe Symlink Creation** (lines 1161-1169):
```java
if (entry.isSymbolicLink()) {
    String canonicalTargetPath = getCanonicalPath(entry.getLinkName(), outputDir);
    Files.createSymbolicLink(
        FileSystems.getDefault().getPath(outputDir.getPath(), entry.getName()),
        FileSystems.getDefault().getPath(canonicalTargetPath));
    return;
}
```

**4. Safe Hardlink Creation** (lines 1178-1183):
```java
if (entry.isLink()) {
    String canonicalTargetPath = getCanonicalPath(entry.getLinkName(), outputDir);
    File src = new File(canonicalTargetPath);
    HardLink.createHardLink(src, outputFile);
    return;
}
```

### Attack Scenario Analysis

**Scenario 1: Direct Path Traversal**
```
Entry name: "../../etc/passwd"
```
- Line 1133: `outputFile = new File(outputDir, "../../etc/passwd")`
- Line 1134: `outputFile.getCanonicalPath()` resolves to `/etc/passwd`
- Line 1134: Check fails: `/etc/passwd` does not start with `/tmp/extract/`
- Result: ✅ Exception thrown

**Scenario 2: Symlink to Outside Directory**
```
Entry: symlink "link" -> "/etc/passwd"
```
- Line 1134: Entry path validated ✅
- Line 1140: `getCanonicalPath("/etc/passwd", outputDir)` returns `/etc/passwd`
- Line 1141: Check fails: `/etc/passwd` does not start with `/tmp/extract/`
- Result: ✅ Exception thrown

**Scenario 3: Symlink with Relative Traversal**
```
Entry: symlink "link" -> "../../etc/passwd"
```
- Line 1134: Entry path validated ✅
- Line 1140: `getCanonicalPath("../../etc/passwd", outputDir)`
  - Creates `new File(outputDir, "../../etc/passwd")`
  - `getCanonicalPath()` resolves to `/etc/passwd`
- Line 1141: Check fails
- Result: ✅ Exception thrown

**Scenario 4: Symlink Inside + File Traversing Through It**
```
Entry 1: symlink "link" -> "subdir"
Entry 2: file "link/../../../etc/passwd"
```
- Entry 1:
  - Line 1140: `getCanonicalPath("subdir", outputDir)` = `/tmp/extract/subdir`
  - Line 1141: Check passes ✅
  - Line 1167: Symlink created: `/tmp/extract/link` -> `/tmp/extract/subdir`
- Entry 2:
  - Line 1133: `outputFile = new File(outputDir, "link/../../../etc/passwd")`
  - Line 1134: `getCanonicalPath()` resolves `..` components in PATH, not filesystem
  - Result: `/tmp/extract/link/../../../etc/passwd` → `/etc/passwd`
  - Line 1134: Check fails
- Result: ✅ Exception thrown

**Note:** `getCanonicalPath()` resolves path components (`..`, `.`) but does NOT follow symlinks when constructing the path string. It only follows symlinks if they already exist in the path components, but the validation happens BEFORE the symlink is created.

**Scenario 5: Hardlink to Outside Directory**
```
Entry: hardlink "link" -> "/etc/passwd"
```
- Same validation as symlinks
- Result: ✅ Exception thrown

**Scenario 6: Symlink Pointing to Extraction Directory Itself**
```
Entry: symlink "link" -> "."
```
- Line 1140: `getCanonicalPath(".", outputDir)` = `/tmp/extract`
- Line 1141: Check: `/tmp/extract`.startsWith(`/tmp/extract/`)
- Note the trailing slash!
- Result: ✅ Exception thrown (canonical path without trailing slash doesn't match)

### Verdict

✅ **HIGHLY SECURE**

Comprehensive protection against:
- ✅ Path traversal via `..` in entry names
- ✅ Absolute paths in entry names
- ✅ Symlink targets pointing outside destination
- ✅ Hardlink targets pointing outside destination
- ✅ Symlink pointing to destination directory itself
- ✅ Complex combinations of symlinks and path traversal

**This is the gold standard implementation.**

---

## 4. FileUtil.unTar() - Native tar Implementation

**File:** `hadoop-common-project/hadoop-common/src/main/java/org/apache/hadoop/fs/FileUtil.java`

### Implementation Details

Entry points:
- `unTarUsingTar(InputStream, File, boolean)` - lines 1035-1051
- `unTarUsingTar(File, File, boolean)` - lines 1053-1084

Used on:
- Unix/Linux systems (default)

### Security Controls

The code shells out to the native `tar` command:

```bash
# For gzipped archives (line 1040-1045):
gzip -dc | (cd '/path/to/dest' && tar -x)

# For regular tar archives (line 1064-1073):
cd '/path/to/dest' && tar -xf '/path/to/source.tar'
```

**Security measures:**
1. Uses `makeSecureShellPath()` to escape shell metacharacters (lines 1043, 1058, 1065)
2. Changes to destination directory before extraction
3. No additional tar security flags

### Vulnerability Analysis

**Security depends entirely on the system's tar implementation:**

**Modern tar versions (GNU tar 1.27+, released 2013):**
- ✅ Strips leading `/` from absolute paths by default
- ✅ Handles `..` in paths safely
- ⚠️ May still follow symlinks without `--no-absolute-names` flag

**Older tar versions (< 1.27):**
- ⚠️ May extract absolute paths as-is
- ⚠️ May follow symlinks in archives
- ⚠️ May not sanitize `..` properly

**BSD tar / libarchive:**
- ✅ Generally safe by default
- ✅ Refuses absolute paths and `..` sequences
- Behavior varies by version

### Missing Security Flags

The implementation does not use modern tar security flags:

| Flag | Purpose | Status |
|------|---------|--------|
| `--no-absolute-names` | Strip leading `/` | ❌ Not used |
| `--no-overwrite-dir` | Don't replace existing directories | ❌ Not used |
| `-P` (inverse) | Allow absolute paths | ❌ Not used (good) |

### Verdict

⚠️ **SECURITY UNKNOWN - DEPENDS ON TAR VERSION**

**Risks:**
- Older systems may be vulnerable
- Behavior is inconsistent across platforms
- No explicit security hardening

**Recommendations:**

1. **Add security flags to tar command:**
```java
untarCommand.append("tar -x --no-absolute-names --no-overwrite-dir ");
```

2. **Or prefer Java implementation:**
Force the use of `unTarUsingJava()` for security-critical operations

3. **Add validation:**
After extraction, verify no files were created outside the destination directory

---

## 5. Comparative Analysis

| Function | Path Traversal | Symlink Validation | Hardlink Validation | Creates Symlinks | Overall |
|----------|----------------|-------------------|-------------------|------------------|---------|
| `RunJar.unJar()` | ✅ Protected | N/A (JAR doesn't support) | N/A | ❌ No | ✅ Secure |
| `FileUtil.unZip()` | ✅ Protected | ❌ Not checked | ❌ Not checked | ❌ No | ⚠️ Safe in practice |
| `FileUtil.unTar()` (Java) | ✅ Protected | ✅ Validated | ✅ Validated | ✅ Yes | ✅ Highly secure |
| `FileUtil.unTar()` (Native) | ⚠️ Depends on tar | ⚠️ Depends on tar | ⚠️ Depends on tar | ✅ Yes | ⚠️ Unknown |

---

## 6. Recommendations

### Immediate Actions

1. **Add symlink validation to FileUtil.unZip()**
   - Detect symlink entries via Unix mode bits
   - Validate symlink targets before creation
   - Create actual symlinks (optional, or continue extracting as files)

2. **Harden FileUtil.unTarUsingTar()**
   - Add `--no-absolute-names` flag
   - Add `--no-overwrite-dir` flag
   - Consider deprecating in favor of Java implementation

3. **Document security guarantees**
   - Clearly document which functions handle symlinks
   - Document platform-specific behavior differences

### Long-term Improvements

1. **Standardize symlink handling**
   - All unpacking functions should handle symlinks consistently
   - Either all create symlinks (with validation) or none do

2. **Add post-extraction validation**
   - Verify no files exist outside destination directory
   - Detect and report anomalies

3. **Consider deprecating native tar**
   - Java implementation is more secure and consistent
   - Reduces platform-specific vulnerabilities

4. **Add security tests**
   - Test with malicious archives containing:
     - Path traversal sequences
     - Absolute paths
     - Symlinks pointing outside destination
     - Hardlinks pointing outside destination
     - Combinations of above

---

## 7. Test Artifacts

### Python PoC

Created malicious ZIP files demonstrating:
1. Symlink escape attack
2. Direct path traversal
3. Symlink + traversal combination

File: `zip_symlink_poc.py`

**Results:**
- All attacks blocked by canonical path validation ✅
- Symlinks not created (extracted as regular files) ✅

### Malicious Archive Examples

Generated test files:
- `malicious_symlink_escape.zip` - Symlink to `../../etc`
- `malicious_direct_traversal.zip` - Files with `../` in names
- `malicious_symlink_traversal.zip` - Symlink + traversal combo

---

## 8. Conclusion

**Overall Assessment: MOSTLY SECURE**

The Hadoop unpacking functions have good path traversal protection. The main findings:

1. **RunJar.unJar()**: ✅ Fully secure for its use case (JAR files)

2. **FileUtil.unZip()**: ✅ Safe in practice, but symlink handling is incomplete
   - Not currently vulnerable because symlinks aren't created
   - Should add explicit symlink validation for completeness

3. **FileUtil.unTar() - Java**: ✅ Excellent security, gold standard implementation
   - Comprehensive validation of all entry types
   - Should be used as reference for other functions

4. **FileUtil.unTar() - Native**: ⚠️ Security depends on system tar version
   - Should be hardened with security flags
   - Consider deprecating in favor of Java implementation

**Risk Level:** LOW to MEDIUM
- Current implementations are safe against common attacks
- Native tar implementation introduces platform-specific risks
- ZIP handling could be more robust

**Priority Fixes:**
1. HIGH: Add security flags to native tar implementation
2. MEDIUM: Add symlink validation to unZip()
3. LOW: Standardize symlink handling across all functions
