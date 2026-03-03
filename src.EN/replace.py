#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JAES.java の「コメント以外」の日本語文字列を英語に置換するスクリプト。
- Javaのコメント(//, /* */)は一切変更しない
- Javaの文字列リテラル("...")の中身だけを置換
- 置換は「文字列全体が一致」した場合のみ（誤爆防止）
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, Tuple


REPLACEMENTS: Dict[str, str] = {
    # ===== エラーメッセージ・状態表示 =====
    "⚠ キーディレクトリ作成に失敗しました: ": "⚠ Failed to create key directory: ",
    "公開鍵のエクスポートに失敗しました: ": "Failed to export public key: ",
    "設定ファイル指定の公開鍵を使用: ": "Using public key specified in config file: ",
    "鍵ディレクトリ準備に失敗: ": "Failed to prepare key directory: ",
    "❌ ファイルが存在しません": "❌ File does not exist",
    "処理をキャンセルしました。メニューに戻ります。": "Operation canceled. Returning to menu.",
    "❌ PNGが不正です": "❌ Invalid PNG file",
    "❌ PNG内データ長が不正": "❌ Invalid embedded data length in PNG",
    "ℹ ブロックチェーンデータが見つかりません": "ℹ No blockchain data found",
    "❌ チェーンに不整合があります": "❌ Blockchain integrity check failed",
    "ブロックチェーンデータが見つかりませんでした: ": "Blockchain data not found: ",
    "コンソールが利用できません（IDE実行やリダイレクトでは使用不可）": "Console is not available (cannot be used in IDE or redirected execution)",
    "画面クリアに失敗しました: ": "Failed to clear console: ",
    "コンソールが使用できません": "Console is not available",
    "パスフレーズが一致しません": "Passphrases do not match",
    "⚠ エラー: ": "⚠ Error: ",
    "⚠ 実行エラー: ": "⚠ Runtime error: ",

    # ===== メニュー表示 =====
    "ポータブルモード:有効": "Portable mode: Enabled",
    "ポータブルモード:無効": "Portable mode: Disabled",
    "現在使用中の公開鍵: ": "Current public key: ",
    "\nモードを選択してください:": "\nSelect mode:",
    "1: 暗号化（jdec出力）": "1: Encrypt (output .jdec)",
    "2: 復号化（jdec入力）": "2: Decrypt (.jdec input)",
    "3: 暗号化（PNG出力）": "3: Encrypt (output PNG)",
    "4: 復号化（PNG入力) ": "4: Decrypt (PNG input) ",
    "5: ブロックチェーン検証（.jdec / .jpng）": "5: Verify blockchain (.jdec / .jpng)",
    "6: ブロックチェーンをエクスポート": "6: Export blockchain",
    "7: 終了": "7: Exit",
    "\n選択 >> ": "\nSelect >> ",

    # ===== 入力プロンプト =====
    "暗号化するファイルのパス: ": "Path of file to encrypt: ",
    ".jdecファイルのパス: ": "Path to .jdec file: ",
    "入力PNGファイルのパス: ": "Path to input PNG file: ",
    "検証するファイルのパス（.jdec / .jpng）: ": "Path of file to verify (.jdec / .jpng): ",
    "エクスポートするファイルのパス（.jdec / .jpng）: ": "Path of file to export (.jdec / .jpng): ",
    "メモ（任意）: ": "Memo (optional): ",
    "秘密鍵のパスフレーズ: ": "Private key passphrase: ",
    "もう一度入力してください: ": "Enter again: ",

    # ===== 成功メッセージ =====
    "✅ 暗号化完了（チェーン継承）: ": "✅ Encryption completed (chain inherited): ",
    "✅ 復号完了（チェーン追記済）: ": "✅ Decryption completed (chain updated): ",
    "✅ 暗号化結果をPNGに出力（チェーン継承・LastUpdated付）: ": "✅ Encryption result exported to PNG (chain inherited, LastUpdated added): ",
    "✅ PNGから復号完了・チェーン更新＆メタ更新済み: ": "✅ Decrypted from PNG (chain and metadata updated): ",
    "ブロックチェーンをエクスポートしました。": "Blockchain exported successfully.",
    "👋 終了します。": "👋 Exiting.",
    "❌ 無効な選択です": "❌ Invalid selection",
# ===== SplitMerge.java =====
"⚠ 設定ディレクトリ作成に失敗しました: ": "⚠ Failed to create configuration directory: ",
"分割設定が無効のため分割しません。": "Split is disabled in configuration. Skipping split.",
"分割設定が無効のため結合しません。": "Split is disabled in configuration. Skipping merge.",
"パート数不一致": "Part count mismatch",
" が改ざんされています": " has been tampered with",

}


def translate_java_strings_preserving_comments(src: str, mapping: Dict[str, str]) -> Tuple[str, int]:
    """
    コメントはそのまま、"..." 文字列リテラル内だけ置換する。
    置換は「文字列の中身が mapping のキーと完全一致」したときだけ。
    """
    out = []
    i = 0
    n = len(src)
    replaced_count = 0

    NORMAL = 0
    LINE_COMMENT = 1
    BLOCK_COMMENT = 2
    STRING = 3
    CHAR = 4

    state = NORMAL
    string_buf = []  # STRING内の中身(引用符なし)を集める

    def is_escaped(s: str, idx: int) -> bool:
        """s[idx] がバックスラッシュでエスケープされているか（連続\の奇数判定）"""
        backslashes = 0
        j = idx - 1
        while j >= 0 and s[j] == '\\':
            backslashes += 1
            j -= 1
        return (backslashes % 2) == 1

    while i < n:
        ch = src[i]

        if state == NORMAL:
            # コメント開始判定（ただし文字列外のみ）
            if ch == '/' and i + 1 < n and src[i + 1] == '/':
                state = LINE_COMMENT
                out.append(ch)
                out.append(src[i + 1])
                i += 2
                continue
            if ch == '/' and i + 1 < n and src[i + 1] == '*':
                state = BLOCK_COMMENT
                out.append(ch)
                out.append(src[i + 1])
                i += 2
                continue

            # 文字列開始
            if ch == '"':
                state = STRING
                out.append(ch)  # opening quote
                string_buf = []
                i += 1
                continue

            # char literal（念のため）
            if ch == "'":
                state = CHAR
                out.append(ch)
                i += 1
                continue

            out.append(ch)
            i += 1
            continue

        if state == LINE_COMMENT:
            out.append(ch)
            i += 1
            if ch == '\n':
                state = NORMAL
            continue

        if state == BLOCK_COMMENT:
            out.append(ch)
            i += 1
            if ch == '*' and i < n and src[i] == '/':
                out.append(src[i])
                i += 1
                state = NORMAL
            continue

        if state == CHAR:
            # char はそのまま通す（終端 ' を探す）
            out.append(ch)
            i += 1
            if ch == "'" and not is_escaped(src, i - 1):
                state = NORMAL
            continue

        if state == STRING:
            # 終端 "
            if ch == '"' and not is_escaped(src, i):
                # 文字列確定 -> 置換判定
                original = ''.join(string_buf)
                replaced = mapping.get(original, original)
                if replaced != original:
                    replaced_count += 1
                out.append(replaced)
                out.append('"')  # closing quote
                state = NORMAL
                i += 1
                continue

            # 通常文字（エスケープ含め、そのまま中身として保持）
            string_buf.append(ch)
            i += 1
            continue

    return ''.join(out), replaced_count


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Translate Japanese Java string literals to English (excluding comments).")
    parser.add_argument("input", type=Path, help="Input .java file path (e.g., JAES.java)")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Output file path (default: <input>.en.java)")
    parser.add_argument("--inplace", action="store_true", help="Overwrite the input file in place")
    args = parser.parse_args()

    inp: Path = args.input
    if not inp.exists():
        raise SystemExit(f"Input file not found: {inp}")

    src = inp.read_text(encoding="utf-8", errors="strict")
    new_src, count = translate_java_strings_preserving_comments(src, REPLACEMENTS)

    if args.inplace:
        outp = inp
    else:
        outp = args.output if args.output else inp.with_name(inp.stem + ".en" + inp.suffix)

    outp.write_text(new_src, encoding="utf-8", errors="strict")
    print(f"Done. Replaced {count} string literal(s). Output: {outp}")


if __name__ == "__main__":
    main()