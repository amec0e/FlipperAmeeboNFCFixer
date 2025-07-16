#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Flipper Ameebo NFC Fixer
Automatically fixes Password, PACK, BCC0, BCC1, and UID issues in .nfc files only
Creates backups in a dedicated folder before making changes
"""

import os
import re
import sys
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def create_backup_folder(base_directory):
    """Create a backup folder with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_folder = base_directory / f"nfc_backups_{timestamp}"
    backup_folder.mkdir(exist_ok=True)
    return backup_folder

def backup_file(filepath, backup_folder):
    """Create a backup of the original file in the backup folder"""
    try:
        # Maintain relative directory structure in backup
        relative_path = filepath.relative_to(filepath.parents[len(filepath.parents) - 1])
        backup_path = backup_folder / relative_path
        
        # Create subdirectories if needed
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Copy the file
        shutil.copy2(filepath, backup_path)
        return backup_path
    except Exception as e:
        print(f"Warning: Could not create backup for {filepath}: {e}")
        return None

def extract_pages_from_nfc(filepath):
    """Extract pages 0, 1, 2, 133, 134 from .nfc file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        pages = {}
        lines = content.split('\n')
        
        for line in lines:
            page_match = re.search(r'Page\s+(\d+):\s*([0-9A-Fa-f\s]+)', line)
            if page_match:
                page_num = int(page_match.group(1))
                page_data = page_match.group(2).replace(' ', '')
                pages[page_num] = page_data
        
        return pages, content, lines
            
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return None, None, None

def calculate_password_from_uid(uid_bytes):
    """Calculate expected password from UID"""
    if len(uid_bytes) < 7:
        return None
    
    sn0, sn1, sn2, sn3, sn4, sn5, sn6 = uid_bytes[0], uid_bytes[1], uid_bytes[2], uid_bytes[3], uid_bytes[4], uid_bytes[5], uid_bytes[6]
    
    pwd = []
    pwd.append(sn1 ^ sn3 ^ 0xAA)  # SN1 ^ SN3 ^ 0xAA
    pwd.append(sn2 ^ sn4 ^ 0x55)  # SN2 ^ SN4 ^ 0x55
    pwd.append(sn3 ^ sn5 ^ 0xAA)  # SN3 ^ SN5 ^ 0xAA
    pwd.append(sn4 ^ sn6 ^ 0x55)  # SN4 ^ SN6 ^ 0x55
    
    return bytes(pwd)

def generate_new_uid():
    """Generate a new valid UID that doesn't have 0x88 in SN3 position"""
    import random
    
    # Generate random bytes, ensuring SN3 (4th byte) is not 0x88
    uid_bytes = []
    for i in range(7):
        if i == 3:  # SN3 position - avoid 0x88
            byte_val = random.randint(0, 255)
            while byte_val == 0x88:
                byte_val = random.randint(0, 255)
            uid_bytes.append(byte_val)
        else:
            uid_bytes.append(random.randint(0, 255))
    
    return uid_bytes

def validate_bcc_calculations(pages):
    """Validate both BCC0 and BCC1 calculations"""
    if not pages or 0 not in pages or 1 not in pages or 2 not in pages:
        return False, "Missing pages", False, False
    
    page0 = bytes.fromhex(pages[0])  # SN0 SN1 SN2 BCC0
    page1 = bytes.fromhex(pages[1])  # SN3 SN4 SN5 SN6
    page2 = bytes.fromhex(pages[2])  # BCC1 INT LCK LCK
    
    if len(page0) < 4 or len(page1) < 4 or len(page2) < 1:
        return False, "Invalid page lengths", False, False
    
    # Extract values
    sn0, sn1, sn2, bcc0_actual = page0[0], page0[1], page0[2], page0[3]
    sn3, sn4, sn5, sn6 = page1[0], page1[1], page1[2], page1[3]
    bcc1_actual = page2[0]
    
    # Calculate expected BCC values
    ct = 0x88  # Cascade Tag for NTAG215
    bcc0_expected = ct ^ sn0 ^ sn1 ^ sn2
    bcc1_expected = sn3 ^ sn4 ^ sn5 ^ sn6
    
    # Check both BCC values
    bcc0_valid = bcc0_actual == bcc0_expected
    bcc1_valid = bcc1_actual == bcc1_expected
    
    if bcc0_valid and bcc1_valid:
        return True, f"BCC0=0x{bcc0_actual:02X} ✓, BCC1=0x{bcc1_actual:02X} ✓", True, True
    elif bcc0_valid and not bcc1_valid:
        return False, f"BCC0=0x{bcc0_actual:02X} ✓, BCC1=0x{bcc1_actual:02X} ✗ (expected 0x{bcc1_expected:02X})", True, False
    elif not bcc0_valid and bcc1_valid:
        return False, f"BCC0=0x{bcc0_actual:02X} ✗ (expected 0x{bcc0_expected:02X}), BCC1=0x{bcc1_actual:02X} ✓", False, True
    else:
        return False, f"BCC0=0x{bcc0_actual:02X} ✗ (expected 0x{bcc0_expected:02X}), BCC1=0x{bcc1_actual:02X} ✗ (expected 0x{bcc1_expected:02X})", False, False

def validate_password_and_pack(pages):
    """Validate password and PACK"""
    if not pages or 0 not in pages or 1 not in pages or 133 not in pages or 134 not in pages:
        return False, "Missing password/PACK pages", False, False
    
    page0 = bytes.fromhex(pages[0])  # SN0 SN1 SN2 BCC0
    page1 = bytes.fromhex(pages[1])  # SN3 SN4 SN5 SN6
    page133 = bytes.fromhex(pages[133])  # Password
    page134 = bytes.fromhex(pages[134])  # PACK
    
    if len(page0) < 4 or len(page1) < 4 or len(page133) < 4 or len(page134) < 4:
        return False, "Invalid page lengths", False, False
    
    # Build UID from pages
    uid = page0[:3] + page1[:4]  # SN0 SN1 SN2 + SN3 SN4 SN5 SN6
    
    # Calculate expected password
    expected_password = calculate_password_from_uid(uid)
    actual_password = page133[:4]  # First 4 bytes of page 133
    
    # Check PACK (should always be 80 80 00 00)
    expected_pack = bytes([0x80, 0x80, 0x00, 0x00])
    actual_pack = page134[:4]  # First 4 bytes of page 134
    
    password_valid = actual_password == expected_password
    pack_valid = actual_pack == expected_pack
    
    password_hex = ' '.join(f'{b:02X}' for b in actual_password)
    expected_password_hex = ' '.join(f'{b:02X}' for b in expected_password)
    pack_hex = ' '.join(f'{b:02X}' for b in actual_pack)
    
    if password_valid and pack_valid:
        return True, f"PWD={password_hex} ✓, PACK={pack_hex} ✓", True, True
    elif password_valid and not pack_valid:
        return False, f"PWD={password_hex} ✓, PACK={pack_hex} ✗ (expected 80 80 00 00)", True, False
    elif not password_valid and pack_valid:
        return False, f"PWD={password_hex} ✗ (expected {expected_password_hex}), PACK={pack_hex} ✓", False, True
    else:
        return False, f"PWD={password_hex} ✗ (expected {expected_password_hex}), PACK={pack_hex} ✗ (expected 80 80 00 00)", False, False

def check_uid_comprehensive(pages, filepath):
    """Comprehensive UID validation: 4th position, BCC, password, and PACK"""
    if not pages or 0 not in pages or 1 not in pages:
        return False, "Missing required pages", "", {"sn3": False, "bcc0": False, "bcc1": False, "password": False, "pack": False}
    
    # Build UID from pages
    page0 = bytes.fromhex(pages[0])
    page1 = bytes.fromhex(pages[1])
    uid = page0[:3] + page1[:4]  # SN0 SN1 SN2 + SN3 SN4 SN5 SN6
    
    if len(uid) < 7:
        return False, "Invalid UID length", "", {"sn3": False, "bcc0": False, "bcc1": False, "password": False, "pack": False}
    
    # Check 4th byte (SN3 - first byte of page 1)
    sn3 = uid[3]  # This is SN3
    uid_hex = ' '.join(f'{b:02X}' for b in uid)
    
    # Validate BCC calculations
    bcc_valid, bcc_msg, bcc0_valid, bcc1_valid = validate_bcc_calculations(pages)
    
    # Validate password and PACK
    pwd_pack_valid, pwd_pack_msg, password_valid, pack_valid = validate_password_and_pack(pages)
    
    # Check 4th position issue (SN3 = 0x88)
    has_position_issue = sn3 == 0x88
    sn3_valid = not has_position_issue
    
    # Determine overall status
    all_valid = sn3_valid and bcc_valid and pwd_pack_valid
    
    if has_position_issue:
        sn3_status = f"SN3=0x88 (PROBLEM!)"
    else:
        sn3_status = f"SN3=0x{sn3:02X} (OK)"
    
    status = f"{sn3_status} + {bcc_msg} + {pwd_pack_msg}"
    
    problem_details = {
        "sn3": sn3_valid,
        "bcc0": bcc0_valid,
        "bcc1": bcc1_valid,
        "password": password_valid,
        "pack": pack_valid
    }
    
    return all_valid, status, uid_hex, problem_details

def fix_nfc_file(filepath, backup_folder, fix_uid=True, fix_bcc=True, fix_password=True, fix_pack=True):
    """Fix all issues in an NFC file"""
    pages, original_content, lines = extract_pages_from_nfc(filepath)
    
    if not pages:
        return False, "Could not read file", {}
    
    # Check if we have required pages
    if 0 not in pages or 1 not in pages:
        return False, "Missing required pages 0 or 1", {}
    
    changes_made = []
    issue_types = {
        'sn3': False,
        'bcc0': False,
        'bcc1': False,
        'password': False,
        'pack': False
    }
    
    # Extract current UID structure
    page0_hex = pages[0]
    page1_hex = pages[1]
    
    if len(page0_hex) < 8 or len(page1_hex) < 8:
        return False, "Invalid page format", {}
    
    # Convert to bytes for easier manipulation
    page0_bytes = bytes.fromhex(page0_hex)
    page1_bytes = bytes.fromhex(page1_hex)
    
    sn0, sn1, sn2, current_bcc0 = page0_bytes[0], page0_bytes[1], page0_bytes[2], page0_bytes[3]
    sn3, sn4, sn5, sn6 = page1_bytes[0], page1_bytes[1], page1_bytes[2], page1_bytes[3]
    
    # Check if UID needs fixing (SN3 = 0x88)
    if fix_uid and sn3 == 0x88:
        # Generate new UID
        new_uid = generate_new_uid()
        sn0, sn1, sn2, sn3, sn4, sn5, sn6 = new_uid
        changes_made.append(f"Generated new UID (old SN3 was 0x88)")
        issue_types['sn3'] = True
    
    # Calculate correct BCC values
    ct = 0x88
    correct_bcc0 = ct ^ sn0 ^ sn1 ^ sn2
    correct_bcc1 = sn3 ^ sn4 ^ sn5 ^ sn6
    
    # Fix BCC0 if needed
    if fix_bcc and current_bcc0 != correct_bcc0:
        changes_made.append(f"Fixed BCC0: {current_bcc0:02X} -> {correct_bcc0:02X}")
        issue_types['bcc0'] = True
    
    # Fix BCC1 if needed
    if fix_bcc and 2 in pages:
        page2_bytes = bytes.fromhex(pages[2])
        if len(page2_bytes) >= 1:
            current_bcc1 = page2_bytes[0]
            if current_bcc1 != correct_bcc1:
                changes_made.append(f"Fixed BCC1: {current_bcc1:02X} -> {correct_bcc1:02X}")
                issue_types['bcc1'] = True
    
    # Calculate correct password
    uid_bytes = [sn0, sn1, sn2, sn3, sn4, sn5, sn6]
    correct_password = list(calculate_password_from_uid(uid_bytes))
    
    # Fix password if needed
    if fix_password and 133 in pages:
        page133_bytes = bytes.fromhex(pages[133])
        if len(page133_bytes) >= 4:
            current_password = list(page133_bytes[:4])
            if current_password != correct_password:
                pwd_old = ' '.join(f'{b:02X}' for b in current_password)
                pwd_new = ' '.join(f'{b:02X}' for b in correct_password)
                changes_made.append(f"Fixed Password: {pwd_old} -> {pwd_new}")
                issue_types['password'] = True
    
    # Fix PACK if needed
    correct_pack = [0x80, 0x80, 0x00, 0x00]
    if fix_pack and 134 in pages:
        page134_bytes = bytes.fromhex(pages[134])
        if len(page134_bytes) >= 4:
            current_pack = list(page134_bytes[:4])
            if current_pack != correct_pack:
                pack_old = ' '.join(f'{b:02X}' for b in current_pack)
                pack_new = ' '.join(f'{b:02X}' for b in correct_pack)
                changes_made.append(f"Fixed PACK: {pack_old} -> {pack_new}")
                issue_types['pack'] = True
    
    if not changes_made:
        return True, "No changes needed", {}
    
    # Create backup before making changes
    backup_path = backup_file(filepath, backup_folder)
    
    # Apply fixes to the content
    new_lines = []
    for line in lines:
        page_match = re.search(r'Page\s+(\d+):\s*([0-9A-Fa-f\s]+)', line)
        if page_match:
            page_num = int(page_match.group(1))
            
            if page_num == 0:
                # Fix Page 0: SN0 SN1 SN2 BCC0
                new_page0 = f"{sn0:02X} {sn1:02X} {sn2:02X} {correct_bcc0:02X}"
                new_line = f"Page 0: {new_page0}"
                new_lines.append(new_line)
            elif page_num == 1:
                # Fix Page 1: SN3 SN4 SN5 SN6
                new_page1 = f"{sn3:02X} {sn4:02X} {sn5:02X} {sn6:02X}"
                new_line = f"Page 1: {new_page1}"
                new_lines.append(new_line)
            elif page_num == 2:
                # Fix Page 2: BCC1 INT LCK LCK
                page2_bytes = bytes.fromhex(pages[2])
                new_page2 = f"{correct_bcc1:02X} {page2_bytes[1]:02X} {page2_bytes[2]:02X} {page2_bytes[3]:02X}"
                new_line = f"Page 2: {new_page2}"
                new_lines.append(new_line)
            elif page_num == 133:
                # Fix Page 133: Password
                new_page133 = f"{correct_password[0]:02X} {correct_password[1]:02X} {correct_password[2]:02X} {correct_password[3]:02X}"
                new_line = f"Page 133: {new_page133}"
                new_lines.append(new_line)
            elif page_num == 134:
                # Fix Page 134: PACK
                new_page134 = f"{correct_pack[0]:02X} {correct_pack[1]:02X} {correct_pack[2]:02X} {correct_pack[3]:02X}"
                new_line = f"Page 134: {new_page134}"
                new_lines.append(new_line)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    
    # Write the fixed content
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(new_lines))
        
        backup_info = f"backup: {backup_path.name}" if backup_path else "backup failed"
        return True, f"Fixed successfully ({backup_info}). Changes: {'; '.join(changes_made)}", issue_types
    except Exception as e:
        return False, f"Error writing file: {e}", {}

def scan_and_fix_directory(directory, fix_uid=True, fix_bcc=True, fix_password=True, fix_pack=True, dry_run=False):
    """Scan directory and fix all NFC files"""
    directory = Path(directory)
    
    if not directory.exists():
        print(f"Directory {directory} does not exist!")
        return
    
    mode = "DRY RUN" if dry_run else "FIXING"
    print(f"🔧 {mode}: Scanning {directory} for NTAG215 NFC files to fix...\n")
    
    if dry_run:
        print("⚠️  DRY RUN MODE - No files will be modified!\n")
    
    # Create backup folder only if we're actually fixing files
    backup_folder = None
    if not dry_run:
        backup_folder = create_backup_folder(directory)
        backup_full_path = backup_folder.resolve()
    
    all_files = []
    unsupported_files = defaultdict(int)
    
    # Find all .nfc and .bin files
    for ext in ['*.nfc', '*.bin']:
        for filepath in directory.rglob(ext):
            if filepath.suffix.lower() == '.nfc':
                pages, _, _ = extract_pages_from_nfc(filepath)
                is_valid, status, uid_hex, problem_details = check_uid_comprehensive(pages, filepath.relative_to(directory))
                
                if dry_run:
                    # In dry run mode, just show original status
                    all_files.append({
                        'path': filepath.relative_to(directory),
                        'is_valid': is_valid,
                        'status': status,
                        'uid_hex': uid_hex,
                        'problems': problem_details,
                        'was_fixed': False
                    })
                else:
                    # Store original status
                    original_status = status
                    original_valid = is_valid
                    
                    # Actually fix the file if it has problems
                    was_fixed = False
                    if not is_valid:
                        success, message, issue_types = fix_nfc_file(filepath, backup_folder, fix_uid, fix_bcc, fix_password, fix_pack)
                        if success and any(issue_types.values()):
                            was_fixed = True
                    
                    # For display purposes, show the ORIGINAL status (what the problems were)
                    # but mark if it was fixed
                    all_files.append({
                        'path': filepath.relative_to(directory),
                        'is_valid': original_valid,
                        'status': original_status,
                        'uid_hex': uid_hex,
                        'problems': problem_details,
                        'was_fixed': was_fixed
                    })
            
            elif filepath.suffix.lower() == '.bin':
                unsupported_files['.bin'] += 1
    
    # Sort files by name (ascending)
    all_files.sort(key=lambda x: str(x['path']).lower())
    
    # Separate valid and problem files based on ORIGINAL status
    valid_files = [f for f in all_files if f['is_valid']]
    problem_files = [f for f in all_files if not f['is_valid']]
    
    # Display valid files first
    if valid_files:
        print("✅ VALID FILES:")
        print("-" * 70)
        for file_info in valid_files:
            print(f"✅ {file_info['path']}: UID {file_info['uid_hex']} - {file_info['status']}")
    
    # Display problem files grouped together
    if problem_files:
        if valid_files:
            print("\n")
        if dry_run:
            print("🚨 PROBLEM FILES:")
        else:
            print("🚨 PROBLEM FILES (FIXED):")
        print("-" * 70)
        for file_info in problem_files:
            prefix = "🚨" if "SN3=0x88" in file_info['status'] else "⚠️ "
            if not dry_run and file_info['was_fixed']:
                # Show that it was fixed
                print(f"✅ {file_info['path']}: UID {file_info['uid_hex']} - {file_info['status']} (FIXED)")
            else:
                print(f"{prefix} {file_info['path']}: UID {file_info['uid_hex']} - {file_info['status']}")
    
    # Calculate problem statistics based on ORIGINAL problems
    problem_stats = {
        "sn3": 0,
        "bcc0": 0,
        "bcc1": 0,
        "password": 0,
        "pack": 0
    }
    
    for file_info in problem_files:
        problems = file_info['problems']
        if not problems['sn3']:
            problem_stats['sn3'] += 1
        if not problems['bcc0']:
            problem_stats['bcc0'] += 1
        if not problems['bcc1']:
            problem_stats['bcc1'] += 1
        if not problems['password']:
            problem_stats['password'] += 1
        if not problems['pack']:
            problem_stats['pack'] += 1
    
    # Summary
    total_files = len(all_files)
    unsupported_count = sum(unsupported_files.values())
    problem_count = len(problem_files)
    valid_count = len(valid_files)
    fixed_count = len([f for f in problem_files if f.get('was_fixed', False)])
    
    print(f"\n{'='*70}")
    if dry_run:
        print(f"Scan Complete!")
    else:
        print(f"Processing Complete!")
    print(f"Total files checked: {total_files}")
    print(f"Valid files: {valid_count}")
    print(f"Problem files: {problem_count}")
    if not dry_run and fixed_count > 0:
        print(f"Files fixed: {fixed_count}")
    
    if unsupported_count > 0:
        unsupported_list = []
        for ext, count in unsupported_files.items():
            unsupported_list.append(f"{count} {ext} files")
        print(f"Unsupported files: {', '.join(unsupported_list)} (Only Flipper Zero .nfc files are supported)")
    
    if problem_count > 0:
        print(f"\n📊 PROBLEM BREAKDOWN:")
        print(f"   SN3 (0x88 issue):     {problem_stats['sn3']} files")
        print(f"   BCC0 incorrect:       {problem_stats['bcc0']} files")
        print(f"   BCC1 incorrect:       {problem_stats['bcc1']} files")
        print(f"   Password incorrect:   {problem_stats['password']} files")
        print(f"   PACK incorrect:       {problem_stats['pack']} files")
        
        if dry_run:
            print(f"\n⚠️  Found {problem_count} files with issues!")
            print("These files may not be recognized by NFC readers.")
            print("Use --fix to actually modify them.")
        else:
            if backup_folder and fixed_count > 0:
                backup_full_path = backup_folder.resolve()
                print(f"\n✅ {fixed_count} files have been fixed!")
                print(f"📁 All original files backed up to: {backup_full_path}")
            elif problem_count > 0:
                print(f"\nℹ️  {problem_count} files had issues but no changes were made.")
    else:
        print("\n🎉 All files passed validation!")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Fix NTAG215 NFC files (Flipper Zero .nfc format only)')
    parser.add_argument('directory', help='Directory containing NFC files')
    parser.add_argument('--fix', action='store_true', help='Actually fix files (default is dry run)')
    parser.add_argument('--no-uid', action='store_true', help='Skip UID fixes')
    parser.add_argument('--no-bcc', action='store_true', help='Skip BCC fixes')
    parser.add_argument('--no-password', action='store_true', help='Skip password fixes')
    parser.add_argument('--no-pack', action='store_true', help='Skip PACK fixes')
    
    args = parser.parse_args()
    
    # Determine what to fix
    fix_uid = not args.no_uid
    fix_bcc = not args.no_bcc
    fix_password = not args.no_password
    fix_pack = not args.no_pack
    
    dry_run = not args.fix
    
    scan_and_fix_directory(
        args.directory,
        fix_uid=fix_uid,
        fix_bcc=fix_bcc,
        fix_password=fix_password,
        fix_pack=fix_pack,
        dry_run=dry_run
    )

if __name__ == "__main__":
    main()